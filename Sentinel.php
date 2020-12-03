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
use Rose\Arry;

use Rose\Ext\Wind;

if (!Extensions::isInstalled('Wind'))
	return;

/*
**	Sentinel Wind Extension.
*/

class Sentinel
{
	public const ERR_NONE					= 0;
	public const ERR_AUTHORIZATION			= 1;
	public const ERR_CREDENTIALS			= 2;

	private static $loadedSession = false;

	public static function errorName ($code)
	{
		switch ($code)
		{
			case Sentinel::ERR_AUTHORIZATION:
				return 'err_authorization';

			case Sentinel::ERR_CREDENTIALS:
				return 'err_credentials';
		}

		return 'err_none';
	}

	public static function password ($value, $escape=false)
	{
		$conf = Configuration::getInstance();
		$value = \hash($conf->Sentinel->hash ? $conf->Sentinel->hash : 'sha384', $conf->Sentinel->prefix . $value . $conf->Sentinel->suffix);
		if ($escape) $value = Connection::escape($value);
		return $value;
	}

	private static function getPrivileges ($username=null, $both=false)
	{
		$conn = Resources::getInstance()->Database;

		if ($username == null)
		{
			if (!Sentinel::status())
				return new Arry ();

			return $conn->execQuery (
				' SELECT DISTINCT p.privilege_id, p.name FROM ##privileges p'.
				' INNER JOIN ##user_privileges u ON u.privilege_id=p.privilege_id'.
				' WHERE u.user_id='.Session::$data->user->user_id
			)->rows->map(function($i) use(&$both) { return $both ? $i : $i->name; });
		}

		return $conn->execQuery (
			' SELECT DISTINCT p.privilege_id, p.name FROM ##privileges p'.
			' INNER JOIN ##user_privileges u ON u.privilege_id=p.privilege_id'.
			' INNER JOIN ##users s ON s.is_active=1 AND s.user_id=u.user_id AND s.username='.Connection::escape($username).
			' WHERE u.user_id='.Session::$data->user->user_id
		)->rows->map(function($i) use(&$both) { return $both ? $i : $i->name; });
	}

	public static function status()
	{
		if (!self::$loadedSession && !Session::$sessionOpen)
		{
			Session::open(false);
			self::$loadedSession = true;
			Session::close(true);
		}

		return Session::$data->user != null ? true : false;
	}

	public static function login (string $username, ?string $password=null)
	{
		if ($password !== null)
		{
			$data = Resources::getInstance()->Database->execAssoc (
				'SELECT * FROM ##users WHERE is_active=1 AND username='.Connection::escape($username).' AND password='.Sentinel::password($password, true)
			);
		}
		else
		{
			$data = Resources::getInstance()->Database->execAssoc (
				'SELECT * FROM ##users WHERE is_active=1 AND user_id='.Connection::escape($username)
			);
		}

		if (!$data) return Sentinel::ERR_CREDENTIALS;

		if ((int)$data->is_authorized == 0)
			return Sentinel::ERR_AUTHORIZATION;

		Session::open(true);

		Session::$data->user = $data;

		$tmp = Sentinel::getPrivileges(null, true);
		$data->privileges = $tmp->map(function($i) { return $i->name; });
		$data->privilege_ids = $tmp->map(function($i) { return $i->privilege_id; });

		return Sentinel::ERR_NONE;
	}

	public static function manual (Map $data)
	{
		Session::open(true);

		Session::$data->user = $data;

		$data->privileges = $data->has('privileges') ? $data->get('privileges') : new Arry();
		$data->privilege_ids = $data->has('privilege_ids') ? $data->get('privilege_ids') : new Arry();

		return Sentinel::ERR_NONE;
	}

	public static function valid (string $username, string $password)
	{
		$data = Resources::getInstance()->Database->execAssoc (
			'SELECT * FROM ##users WHERE is_active=1 AND username='.Connection::escape($username).' AND password='.Sentinel::password($password, true)
		);

		if (!$data) return Sentinel::ERR_CREDENTIALS;

		if ((int)$data->is_authorized == 0)
			return Sentinel::ERR_AUTHORIZATION;

		return Sentinel::ERR_NONE;
	}

	public static function logout()
	{
		if (!Session::open(false))
			return;

		Session::$data->remove('user');
	}

	public static function reload()
	{
		if (!Session::open(false))
			return;

		$data = Resources::getInstance()->Database->execAssoc (
			'SELECT * FROM ##users WHERE is_active=1 AND user_id='.Session::$data->user->user_id
		);

		if (!$data) return;

		Session::$data->user = $data;

		$tmp = Sentinel::getPrivileges(null, true);
		$data->privileges = $tmp->map(function($i) { return $i->name; });
		$data->privilege_ids = $tmp->map(function($i) { return $i->privilege_id; });
	}

	public static function hasPrivilege ($privilege, $username=null)
	{
		if (!$privilege) return true;

		$conf = Configuration::getInstance();
		$conn = Resources::getInstance()->Database;

		$privilege = Text::split(',', ($conf->Sentinel->master == 'true' ? 'master,' : '').$privilege)->map(function($i) { return Connection::escape($i); })->join(',');

		$count = 0;

		if ($username == null)
		{
			if (!Sentinel::status()) return false;

			$count = $conn->execScalar (
				' SELECT COUNT(*) FROM ##privileges p '.
				' INNER JOIN ##user_privileges up ON up.privilege_id=p.privilege_id'.
				' WHERE up.user_id='.Session::$data->user->user_id.' AND p.name IN ('.$privilege.')'
			);
		}
		else
		{
			$count = $conn->execScalar (
				' SELECT COUNT(*) FROM ##privileges p '.
				' INNER JOIN ##user_privileges up ON up.privilege_id=p.privilege_id'.
				' INNER JOIN ##users u ON u.is_active=1 AND u.username='.Connection::escape($username).' AND up.user_id=u.user_id'.
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
Expr::register('sentinel::password', function($args, $parts, $data)
{
	return Sentinel::password($args->get(1));
});

Expr::register('sentinel::status', function($args, $parts, $data)
{
	return Sentinel::status();
});

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

Expr::register('sentinel::has-privilege', function($args, $parts, $data)
{
	return Sentinel::verifyPrivileges($args->get(1), $args->{2});
});

Expr::register('sentinel::valid', function($args, $parts, $data)
{
	return Sentinel::valid ($args->get(1), $args->get(2)) == Sentinel::ERR_NONE;
});

Expr::register('sentinel::validate', function($args, $parts, $data)
{
	$code = Sentinel::valid ($args->get(1), $args->get(2));

	if ($code != Sentinel::ERR_NONE)
		Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Strings::get('@messages/'.Sentinel::errorName($code)) ]);

	return null;
});

Expr::register('sentinel::login', function($args, $parts, $data)
{
	$code = Sentinel::login ($args->get(1), $args->get(2));

	if ($code != Sentinel::ERR_NONE)
		Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Strings::get('@messages/'.Sentinel::errorName($code)) ]);

	return null;
});

Expr::register('sentinel::login:manual', function($args, $parts, $data)
{
	Sentinel::manual ($args->get(1));
	return null;
});

Expr::register('sentinel::login:forced', function($args, $parts, $data)
{
	$code = Sentinel::login ($args->get(1));

	if ($code != Sentinel::ERR_NONE)
		Wind::reply([ 'response' => Wind::R_VALIDATION_ERROR, 'error' => Strings::get('@messages/'.Sentinel::errorName($code)) ]);

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
