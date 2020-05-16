<?php
/*
**	Rose\Ext\Sentinel
**
**	Copyright (c) 2019-2020, RedStar Technologies, All rights reserved.
**	https://rsthn.com/
**
**	THIS LIBRARY IS PROVIDED BY REDSTAR TECHNOLOGIES "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
**	INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
**	PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL REDSTAR TECHNOLOGIES BE LIABLE FOR ANY
**	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
**	NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
**	OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
**	STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
**	USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

namespace Rose\Ext;

use Rose\Errors\Error;

use Rose\Data\Connection;

use Rose\Configuration;
use Rose\Session;
use Rose\Strings;
use Rose\Resources;
use Rose\Extensions;
use Rose\Text;
use Rose\Expr;
use Rose\Map;

use Rose\Ext\Wind;

if (!Extensions::isInstalled('Wind'))
	return;

/*
**	Sentinel Wind Extension.
*/

class Sentinel
{
	public static function password ($value, $escape=false)
	{
		$conf = Configuration::getInstance();
		$value = \hash('sha384', $conf->Sentinel->prefix . $value . $conf->Sentinel->suffix);
		if ($escape) $value = Connection::escape($value);
		return $value;
	}

	private static function getPrivileges ($username=null)
	{
		$conn = Resources::getInstance()->Database;

		if ($username == null)
		{
			if (!Sentinel::status())
				return new Arry ();

			return $conn->execArray (
				' SELECT DISTINCT p.name FROM ##privileges p'.
				' INNER JOIN ##user_privileges u ON u.privilege_id=p.privilege_id'.
				' WHERE u.user_id='.Session::$data->currentUser->user_id
			)->map(function($i) { return $i->name; });
		}

		return $conn->execArray (
			' SELECT DISTINCT p.name FROM ##privileges p'.
			' INNER JOIN ##user_privileges u ON u.privilege_id=p.privilege_id'.
			' INNER JOIN ##users s ON s.is_active=1 AND s.user_id=u.user_id AND s.username='.Connection::escape($username).
			' WHERE u.user_id='.Session::$data->currentUser->user_id
		)->map(function($i) { return $i->name; });
	}

	public static function status()
	{
		return Session::$data->currentUser != null ? true : false;
	}

	public static function login ($username, $password)
	{
		$data = Resources::getInstance()->Database->execAssoc (
			'SELECT * FROM ##users WHERE username='.Connection::escape($username).' AND password='.Sentinel::password($password, true)
		);

		if (!$data) return false;

		Session::$data->currentUser = $data;
		Session::$data->currentUser->privileges = Sentinel::getPrivileges();

		return true;
	}

	public static function logout()
	{
		Session::$data->remove('currentUser');
	}

	public static function reload()
	{
		if (!Sentinel::status())
			return;

		$data = Resources::getInstance()->Database->execAssoc (
			'SELECT * FROM ##users WHERE user_id='.Session::$data->currentUser->user_id
		);

		if (!$data) return;

		Session::$data->currentUser = $data;
		Session::$data->currentUser->privileges = Sentinel::getPrivileges();
	}

	public static function hasPrivilege ($privilege, $username=null)
	{
		if (!$privilege) return true;

		$privilege = Text::split(',', ($conf->Sentinel->master == 'true' ? 'master,' : '').$privilege)->map(function($i) { return Connection::escape($i); })->join(',');

		$conf = Configuration::getInstance();
		$conn = Resources::getInstance()->Database;

		$count = 0;

		if ($username == null)
		{
			if (!Sentinel::status()) return false;

			$count = $conn->execScalar (
				' SELECT COUNT(*) FROM ##privileges p '.
				' INNER JOIN ##user_privileges up ON up.privilege_id=p.privilege_id'.
				' WHERE up.user_id='.Session::$data->currentUser->user_id.' AND p.name IN ('.$privilege.')'
			);
		}
		else
		{
			$count = $conn->execScalar (
				' SELECT COUNT(*) FROM ##privileges p '.
				' INNER JOIN ##user_privileges up ON up.privilege_id=p.privilege_id'.
				' INNER JOIN ##users u ON u.username='.Connection::escape($username).' AND up.user_id=u.user_id'.
				' WHERE priv.name IN ('.$privilege.')'
			);
		}

		return $count != 0 ? true : false;
	}

	public static function verifyPrivileges ($value, $username=null)
	{
		if (!$username && !Sentinel::status())
			return false;

		$groups = Text::split(',', Text::trim($value ? $value : ''));

		foreach ($groups->__nativeArray as $group)
		{
			$groupFailed = false;

			foreach (Text::split(' ', Text::trim($group))->__nativeArray as $privilege)
			{
				if (!Sentinel::hasPrivilege (Text::trim($privilege), $username))
				{
					$groupFailed = true;
					break;
				}
			}

			if ($groupFailed == false) return true;
		}

		return false;
	}
};

/* ****************************************************************************** */
Expr::register('sentinel::auth-required', function($args, $parts, $data)
{
	if (!Sentinel::status())
		Wind::reply([ 'response' => Wind::R_NOT_AUTHENTICATED ]);

	return null;
});

Expr::register('sentinel::privilege-required', function($args, $parts, $data)
{
	if (!Sentinel::verifyPrivileges($args->get(1)))
		Wind::reply([ 'response' => Sentinel::status() ? Wind::R_PRIVILEGE_REQUIRED : Wind::R_NOT_AUTHENTICATED ]);

	return null;
});

Expr::register('sentinel::password', function($args, $parts, $data)
{
	return Sentinel::password($args->get(1));
});

Expr::register('sentinel::status', function($args, $parts, $data)
{
	return Sentinel::status();
});

Expr::register('sentinel::login', function($args, $parts, $data)
{
	if (!Sentinel::login ($args->get(1), $args->get(2)))
		Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Strings::get('@errors/authentication') ]);

	return null;
});

Expr::register('sentinel::logout', function($args, $parts, $data)
{
	Sentinel::logout();
	return null;
});

Expr::register('sentinel::reload', function($args, $parts, $data)
{
	Sentinel::reload();
	return null;
});
