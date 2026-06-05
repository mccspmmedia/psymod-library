<?php
/**
 * PSYMOD Account helpers and roles.
 *
 * @package PSYMOD_Library
 */

if (! defined('ABSPATH')) {
	exit;
}

if (! defined('PSYMOD_ACCESS_PUBLIC')) {
	define('PSYMOD_ACCESS_PUBLIC', 'public');
}
if (! defined('PSYMOD_ACCESS_REGISTERED')) {
	define('PSYMOD_ACCESS_REGISTERED', 'free_user');
}
if (! defined('PSYMOD_ACCESS_MEMBER')) {
	define('PSYMOD_ACCESS_MEMBER', 'core');
}
if (! defined('PSYMOD_ACCESS_PREMIUM')) {
	define('PSYMOD_ACCESS_PREMIUM', 'pro');
}
if (! defined('PSYMOD_ACCESS_ADMIN_ONLY')) {
	define('PSYMOD_ACCESS_ADMIN_ONLY', 'admin_only');
}

if (! function_exists('psymod_account_get_access_hierarchy')) {
	/**
	 * Get ordered access hierarchy from low to high.
	 *
	 * @return string[]
	 */
	function psymod_account_get_access_hierarchy(): array
	{
		return array(
			PSYMOD_ACCESS_PUBLIC,
			PSYMOD_ACCESS_REGISTERED,
			PSYMOD_ACCESS_MEMBER,
			PSYMOD_ACCESS_PREMIUM,
			PSYMOD_ACCESS_ADMIN_ONLY,
			'admin',
		);
	}
}

if (! function_exists('psymod_account_normalize_access_level')) {
	/**
	 * Normalize and validate access level.
	 */
	function psymod_account_normalize_access_level(string $level): string
	{
		$level   = sanitize_text_field($level);
		$aliases = array(
			'free'       => PSYMOD_ACCESS_REGISTERED,
			'registered' => PSYMOD_ACCESS_REGISTERED,
			'member'     => PSYMOD_ACCESS_MEMBER,
			'premium'    => PSYMOD_ACCESS_PREMIUM,
		);
		if (isset($aliases[$level])) {
			$level = $aliases[$level];
		}

		$allowed = array(
			PSYMOD_ACCESS_PUBLIC,
			PSYMOD_ACCESS_REGISTERED,
			PSYMOD_ACCESS_MEMBER,
			PSYMOD_ACCESS_PREMIUM,
			PSYMOD_ACCESS_ADMIN_ONLY,
			'admin',
		);

		return in_array($level, $allowed, true) ? $level : PSYMOD_ACCESS_PUBLIC;
	}
}

if (! function_exists('psymod_account_get_access_rank')) {
	/**
	 * Get numeric rank for access level.
	 */
	function psymod_account_get_access_rank(string $level): int
	{
		$hierarchy = psymod_account_get_access_hierarchy();
		$index     = array_search(psymod_account_normalize_access_level($level), $hierarchy, true);
		return $index === false ? 0 : (int) $index;
	}
}

if (! function_exists('psymod_account_register_roles')) {
	/**
	 * Register PSYMOD account roles.
	 */
	function psymod_account_register_roles(): void
	{
		$capabilities = array(
			'read'         => true,
			'upload_files' => false,
			'edit_posts'   => false,
			'delete_posts' => false,
		);

		add_role('psymod_free', 'PSYMOD Free', $capabilities);
		add_role('psymod_member', 'PSYMOD Member', $capabilities);
		add_role('psymod_premium', 'PSYMOD Premium', $capabilities);
	}
}

add_action('init', 'psymod_account_register_roles');

if (! function_exists('psymod_account_get_user_level')) {
	/**
	 * Get normalized account level for a user.
	 *
	 * @return string free|member|premium|admin
	 */
	function psymod_account_get_user_level($user_id = 0): string
	{
		static $cache = array();

		$requested_user_id = absint($user_id);
		$current_user      = wp_get_current_user();
		$current_user_id   = $current_user instanceof WP_User ? (int) $current_user->ID : 0;
		$target_user_id    = $requested_user_id > 0 ? $requested_user_id : $current_user_id;
		$cache_key         = $target_user_id > 0 ? $target_user_id : 'guest';

		if (isset($cache[$cache_key])) {
			return (string) $cache[$cache_key];
		}

		$user = get_userdata($target_user_id);
		if (! ($user instanceof WP_User)) {
			$cache[$cache_key] = PSYMOD_ACCESS_PUBLIC;
			return PSYMOD_ACCESS_PUBLIC;
		}

		$roles = (array) $user->roles;

		if (in_array('administrator', $roles, true)) {
			$cache[$cache_key] = 'admin';
			return 'admin';
		}
		if (in_array('pro', $roles, true) || in_array('psymod_premium', $roles, true)) {
			$cache[$cache_key] = PSYMOD_ACCESS_PREMIUM;
			return PSYMOD_ACCESS_PREMIUM;
		}
		if (in_array('core', $roles, true) || in_array('psymod_member', $roles, true)) {
			$cache[$cache_key] = PSYMOD_ACCESS_MEMBER;
			return PSYMOD_ACCESS_MEMBER;
		}
		if (in_array('psymod_free', $roles, true) || is_user_logged_in()) {
			$cache[$cache_key] = PSYMOD_ACCESS_REGISTERED;
			return PSYMOD_ACCESS_REGISTERED;
		}

		$cache[$cache_key] = PSYMOD_ACCESS_PUBLIC;
		return PSYMOD_ACCESS_PUBLIC;
	}
}

if (! function_exists('psymod_account_current_user_access_level')) {
	/**
	 * Get current user access level.
	 */
	function psymod_account_current_user_access_level(): string
	{
		return psymod_account_get_user_level(0);
	}
}

if (! function_exists('psymod_account_user_has_minimum_access')) {
	/**
	 * Check if current user has minimum required access level.
	 */
	function psymod_account_user_has_minimum_access(string $required_level): bool
	{
		$required = psymod_account_normalize_access_level($required_level);
		$current  = psymod_account_current_user_access_level();

		if ($current === 'admin') {
			return true;
		}

		if ($required === PSYMOD_ACCESS_REGISTERED) {
			return is_user_logged_in();
		}

		return psymod_account_get_access_rank($current) >= psymod_account_get_access_rank($required);
	}
}

if (! function_exists('psymod_account_require_access')) {
	/**
	 * Middleware-like guard for protected pages.
	 */
	function psymod_account_require_access(string $level): void
	{
		$required = psymod_account_normalize_access_level($level);
		if (psymod_account_user_has_minimum_access($required)) {
			return;
		}

		wp_safe_redirect(home_url('/login/'));
		exit;
	}
}

if (! function_exists('psymod_account_user_has_access')) {
	/**
	 * Check if current user has required account level.
	 */
	function psymod_account_user_has_access($required_level): bool
	{
		return psymod_account_user_has_minimum_access((string) $required_level);
	}
}

if (! function_exists('psymod_account_render_styles')) {
	/**
	 * Render account UI styles once per page.
	 */
	function psymod_account_render_styles(): string
	{
		static $printed = false;
		if ($printed) {
			return '';
		}
		$printed = true;

		return '<style>'
			. '.psymod-account{max-width:1040px;margin:48px auto;padding:0 20px}'
			. '.psymod-account.psymod-account--auth{max-width:560px;margin:48px auto;padding:0 16px}'
			. 'body .entry-content .psymod-account.psymod-account--auth{max-width:560px!important;width:100%!important;margin:48px auto!important;padding:0 16px!important}'
			. 'body .entry-content .psymod-account.psymod-account--auth .psymod-account-card{max-width:560px!important;width:100%!important;margin:0 auto!important}'
			. '.psymod-account-card{background:#fff;border:1px solid #e5e7eb;border-radius:24px;padding:32px;box-shadow:0 20px 48px rgba(15,23,42,.08)}'
			. '.psymod-account-title{margin:0 0 22px;font-size:32px;line-height:1.1;color:#111827;letter-spacing:-.02em}'
			. '.psymod-account-form{display:flex;flex-direction:column;gap:16px}'
			. '.psymod-account-field{display:flex;flex-direction:column;gap:8px}'
			. '.psymod-account-field span{font-size:14px;line-height:1.3;font-weight:600;color:#334155}'
			. '.psymod-account-input{width:100%;min-height:52px;border:1px solid #d1d5db;border-radius:14px;padding:0 16px;font-size:16px;color:#111827;background:#fff;transition:border-color .2s ease,box-shadow .2s ease}'
			. '.psymod-account-input:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 4px rgba(59,130,246,.15)}'
			. '.psymod-account-button{display:inline-flex;align-items:center;justify-content:center;min-height:48px;padding:0 22px;border:1px solid #111827;border-radius:14px;background:#111827;color:#fff;text-decoration:none;font-weight:700;cursor:pointer;transition:transform .2s ease,box-shadow .2s ease,background-color .2s ease}'
			. '.psymod-account-button:hover{background:#0b1220;transform:translateY(-1px);box-shadow:0 12px 24px rgba(17,24,39,.24)}'
			. '.psymod-account-button:focus-visible{outline:0;box-shadow:0 0 0 4px rgba(59,130,246,.18)}'
			. '.psymod-account-button--primary{background:#111827;color:#fff;border-color:#111827}'
			. '.psymod-account-button--secondary{background:#fff;color:#111827;border-color:#d1d5db;box-shadow:none}'
			. '.psymod-account-button--secondary:hover{background:#f8fafc;border-color:#9ca3af}'
			. '.psymod-account-btn--danger{background:#fff;color:#b91c1c;border-color:#ef4444;box-shadow:none}'
			. '.psymod-account-btn--danger:hover{background:#dc2626;color:#fff;border-color:#dc2626;box-shadow:0 12px 24px rgba(220,38,38,.24)}'
			. '.psymod-account-btn--reactivate{background:#fff;color:#111827;border-color:#111827;box-shadow:none}'
			. '.psymod-account-btn--reactivate:hover{background:#111827;color:#fff;border-color:#111827;box-shadow:0 12px 24px rgba(17,24,39,.24)}'
			. '.psymod-account-form .psymod-account-button{width:100%;min-height:52px}'
			. '.psymod-account-link{color:#2563eb;text-decoration:none;font-weight:600}'
			. '.psymod-account-link:hover{text-decoration:underline}'
			. '.psymod-account-actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:16px}'
			. '.psymod-account-footer{display:flex;flex-wrap:wrap;gap:12px 16px;justify-content:center;margin-top:18px;padding-top:16px;border-top:1px solid #e5e7eb}'
			. '.psymod-account-notice{margin:0 0 14px;color:#4b5563;line-height:1.55}'
			. '.psymod-account-notice--error{padding:10px 12px;border:1px solid #fecaca;background:#fef2f2;color:#991b1b;border-radius:12px}'
			. '.psymod-account-notice--success{padding:10px 12px;border:1px solid #bbf7d0;background:#f0fdf4;color:#166534;border-radius:12px}'
			. '.psymod-locked{max-width:760px;margin:18px auto 0}'
			. '.psymod-locked-card{background:#fff;border:1px solid #e5e7eb;border-radius:18px;padding:28px 24px;text-align:center;box-shadow:0 10px 30px rgba(15,23,42,.06)}'
			. '.psymod-locked-card:hover{box-shadow:0 16px 36px rgba(15,23,42,.1);transform:translateY(-1px);transition:all .2s ease}'
			. '.psymod-locked-icon{font-size:28px;line-height:1;margin:0 0 10px}'
			. '.psymod-locked-title{margin:0 0 8px;font-size:28px;line-height:1.2;color:#111827}'
			. '.psymod-locked-text{margin:0;color:#4b5563;line-height:1.55}'
			. '.psymod-locked-actions{display:flex;flex-wrap:wrap;justify-content:center;gap:10px;margin-top:16px}'
			. '.psymod-locked-button{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:0 16px;border-radius:12px;border:1px solid #111827;background:#111827;color:#fff;text-decoration:none;font-weight:600}'
			. '.psymod-locked-button.is-secondary{background:#fff;color:#111827;border-color:#d1d5db}'
			. '.psymod-material-card{position:relative}'
			. '.psymod-access-badge{position:absolute;top:10px;right:10px;z-index:6;display:inline-flex;align-items:center;justify-content:center;min-height:28px;padding:0 10px;border-radius:999px;font-size:12px;font-weight:700;line-height:1;border:1px solid transparent;box-shadow:0 8px 20px rgba(15,23,42,.12)}'
			. '.psymod-access-badge--registered{background:#eff6ff;color:#1d4ed8;border-color:#bfdbfe}'
			. '.psymod-access-badge--member{background:#fff7ed;color:#9a3412;border-color:#fed7aa}'
			. '.psymod-access-badge--premium{background:#fdf4ff;color:#86198f;border-color:#f5d0fe}'
			. '.psymod-access-badge--admin{background:#111827;color:#fff;border-color:#111827}'
			. '.psymod-account-dashboard{display:flex;flex-direction:column;gap:22px}'
			. '.psymod-account-hero{background:linear-gradient(135deg,#f8fafc,#eef2ff);border:1px solid #e5e7eb;border-radius:28px;padding:34px;display:flex;justify-content:space-between;align-items:center;gap:16px;box-shadow:0 16px 36px rgba(15,23,42,.08)}'
			. '.psymod-account-eyebrow{display:inline-block;margin:0 0 8px;font-size:11px;line-height:1;letter-spacing:.16em;text-transform:uppercase;font-weight:700;color:#64748b}'
			. '.psymod-account-hero h1{margin:0;font-size:38px;line-height:1.1;color:#111827;letter-spacing:-.02em}'
			. '.psymod-account-hero p{margin:10px 0 0;color:#475569;font-size:15px;line-height:1.5}'
			. '.psymod-account-level-badge{display:inline-flex;align-items:center;justify-content:center;min-height:30px;padding:0 12px;border-radius:999px;background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe;font-size:12px;font-weight:700;white-space:nowrap}'
			. '.psymod-account-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}'
			. '.psymod-account-panel{background:#fff;border:1px solid #e5e7eb;border-radius:22px;padding:24px}'
			. '.psymod-account-panel h3{margin:0 0 10px;font-size:22px;line-height:1.2;color:#111827}'
			. '.psymod-account-panel p{margin:0 0 8px;color:#475569;line-height:1.6}'
			. '.psymod-account-subscription{margin:0}'
			. '.psymod-account-subscription-card{background:#fff;border:1px solid #e5e7eb;border-radius:22px;padding:24px;box-shadow:0 12px 30px rgba(15,23,42,.07)}'
			. '.psymod-account-subscription-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin:0 0 14px}'
			. '.psymod-account-subscription-title{margin:0;font-size:24px;line-height:1.2;color:#111827}'
			. '.psymod-account-subscription-status{display:inline-flex;align-items:center;justify-content:center;min-height:28px;padding:0 12px;border-radius:999px;background:#eef2ff;color:#3730a3;font-size:12px;font-weight:700;white-space:nowrap}'
			. '.psymod-account-subscription-status.status-active{background:#dcfce7;color:#166534}'
			. '.psymod-account-subscription-status.status-on-hold{background:#fef9c3;color:#854d0e}'
			. '.psymod-account-subscription-status.status-cancelled,.psymod-account-subscription-status.status-expired{background:#fee2e2;color:#991b1b}'
			. '.psymod-account-subscription-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 16px;margin:0 0 18px}'
			. '.psymod-account-subscription-item{margin:0}'
			. '.psymod-account-subscription-label{display:block;margin:0 0 4px;font-size:12px;line-height:1;letter-spacing:.08em;text-transform:uppercase;font-weight:700;color:#64748b}'
			. '.psymod-account-subscription-value{display:block;font-size:16px;line-height:1.4;color:#0f172a;font-weight:600}'
			. '.psymod-account-subscription-actions{display:flex;flex-wrap:wrap;gap:10px;margin:0}'
			. '.psymod-account-subscription-empty{margin:0;color:#475569;line-height:1.6}'
			. '.psymod-account-subscription-note{margin:10px 0 0;font-size:13px;line-height:1.5;color:#6b7280}'
			. '.psymod-account-recommend{background:#fff;border:1px solid #e5e7eb;border-radius:22px;padding:24px}'
			. '.psymod-account-recommend h3{margin:0 0 8px;font-size:24px;line-height:1.2;color:#111827}'
			. '.psymod-account-recommend p{margin:0;color:#475569;line-height:1.6}'
			. '.psymod-account-next-step{padding:14px 16px;border-radius:14px;background:#f8fafc;border:1px solid #e2e8f0}'
			. '.psymod-account-next-step__title{margin:0 0 6px;font-size:14px;font-weight:700;color:#0f172a}'
			. '.psymod-account-next-step__text{margin:0;color:#475569;font-size:14px;line-height:1.5}'
			. '.psymod-access-status{margin:0}'
			. '.psymod-access-status-card{background:#fff;border:1px solid #e5e7eb;border-radius:16px;padding:20px 22px;box-shadow:0 10px 24px rgba(15,23,42,.06)}'
			. '.psymod-access-status-title{margin:0 0 8px;font-size:24px;line-height:1.2;color:#111827}'
			. '.psymod-access-status-level{display:inline-flex;align-items:center;min-height:28px;padding:0 12px;border-radius:999px;background:#f3f4f6;color:#111827;font-size:13px;font-weight:700;margin:0 0 10px}'
			. '.psymod-account-materials-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}'
			. '.psymod-account-material-card{position:relative;background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:14px 14px 12px;box-shadow:0 8px 18px rgba(15,23,42,.05)}'
			. '.psymod-account-material-title{margin:0 0 8px;font-size:17px;line-height:1.3;color:#111827}'
			. '.psymod-account-material-title a{text-decoration:none;color:inherit}'
			. '.psymod-account-material-excerpt{margin:0;color:#4b5563;line-height:1.5;font-size:14px}'
			. '.psymod-account-cta{display:inline-flex;align-items:center;justify-content:center;min-height:42px;padding:0 14px;border:1px solid #111827;border-radius:10px;background:#111827;color:#fff;text-decoration:none;font-weight:600}'
			. '.psymod-account-material-card .psymod-access-badge{position:static;box-shadow:none;margin:0 0 8px}'
			. '.psymod-favorite-button{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:0 14px;border:1px solid #d1d5db;border-radius:10px;background:#fff;color:#111827;text-decoration:none;font-weight:600;cursor:pointer;transition:all .2s ease}'
			. '.psymod-favorite-button:hover{border-color:#9ca3af;background:#f9fafb}'
			. '.psymod-favorite-button--active{border-color:#fda4af;background:#fff1f2;color:#9f1239}'
			. '.psymod-account-empty{margin:0;color:#6b7280;font-size:14px;line-height:1.5}'
			. '.psymod-account-section{margin:0}'
			. '.psymod-account-section-title{margin:0 0 12px;font-size:22px;line-height:1.2;color:#111827}'
			. '.psymod-pricing-section{max-width:1240px;margin:44px auto;padding:0 20px}'
			. '.psymod-pricing-shell{position:relative;border-radius:34px;padding:34px;background:radial-gradient(120% 140% at 0% 0%,#f8fafc 0%,#eef5ff 48%,#ffffff 100%);border:1px solid rgba(148,163,184,.28);box-shadow:0 24px 64px rgba(15,23,42,.10)}'
			. '.psymod-pricing-shell:before{content:"";position:absolute;inset:14px;border-radius:24px;border:1px solid rgba(255,255,255,.72);pointer-events:none}'
			. '.psymod-pricing-header{text-align:center;max-width:760px;margin:0 auto 28px}'
			. '.psymod-pricing-title{margin:0;font-size:40px;line-height:1.08;letter-spacing:-.02em;color:#0f172a}'
			. '.psymod-pricing-subtitle{margin:12px 0 0;color:#475569;font-size:17px;line-height:1.6}'
			. '.psymod-pricing-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:24px}'
			. '.psymod-pricing-card{position:relative;display:flex;flex-direction:column;gap:18px;min-height:380px;padding:28px;border-radius:30px;background:linear-gradient(180deg,#ffffff 0%,#f8fbff 100%);border:1px solid rgba(148,163,184,.30);box-shadow:0 14px 34px rgba(15,23,42,.09);text-decoration:none;overflow:hidden;isolation:isolate;transition:transform .28s ease,box-shadow .28s ease,border-color .28s ease}'
			. '.psymod-pricing-card:before{content:"";position:absolute;inset:-70% 34% auto auto;width:340px;height:340px;border-radius:50%;background:radial-gradient(circle,rgba(59,130,246,.14),rgba(59,130,246,0));z-index:0;pointer-events:none}'
			. '.psymod-pricing-card:hover{transform:translateY(-6px);box-shadow:0 24px 50px rgba(15,23,42,.16);border-color:rgba(37,99,235,.34)}'
			. '.psymod-pricing-card-link{position:absolute;inset:0;z-index:1;border-radius:30px}'
			. '.psymod-pricing-card-link:focus-visible{outline:none;box-shadow:0 0 0 4px rgba(37,99,235,.2) inset}'
			. '.psymod-pricing-card-media{position:relative;z-index:2;display:flex;align-items:center;justify-content:center;min-height:280px;padding:12px;border-radius:24px;background:#f8fafc;border:1px solid rgba(226,232,240,.92)}'
			. '.psymod-pricing-card-image{display:block;max-width:100%;width:100%;height:100%;max-height:255px;object-fit:contain;object-position:center;border-radius:24px;filter:drop-shadow(0 12px 26px rgba(15,23,42,.12))}'
			. '.psymod-pricing-card-action{position:relative;z-index:2;display:inline-flex;align-items:center;justify-content:center;min-height:50px;padding:0 18px;border-radius:14px;background:#111827;color:#ffffff;text-decoration:none;font-weight:700;line-height:1.2;transition:transform .22s ease,box-shadow .22s ease,background-color .22s ease}'
			. '.psymod-pricing-card-action:hover{background:#0b1220;color:#ffffff;text-decoration:none;transform:translateY(-1px);box-shadow:0 12px 24px rgba(17,24,39,.28)}'
			. '.psymod-pricing-card-action:focus-visible{outline:none;box-shadow:0 0 0 4px rgba(37,99,235,.18),0 12px 24px rgba(17,24,39,.2)}'
			. '@media (max-width:1100px){.psymod-pricing-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.psymod-pricing-card{min-height:360px}.psymod-pricing-card-media{min-height:250px}}'
			. '@media (max-width:720px){.psymod-pricing-section{padding:0 14px;margin:30px auto}.psymod-pricing-shell{padding:24px 16px;border-radius:24px}.psymod-pricing-title{font-size:31px}.psymod-pricing-subtitle{font-size:15px}.psymod-pricing-grid{grid-template-columns:1fr;gap:18px}.psymod-pricing-card{min-height:320px;padding:20px;border-radius:24px}.psymod-pricing-card-link{border-radius:24px}.psymod-pricing-card-media{min-height:210px;padding:10px;border-radius:20px}.psymod-pricing-card-image{max-height:210px;border-radius:20px}.psymod-pricing-card-action{width:100%}}'
			. '@media (max-width:720px){.psymod-account{margin:28px auto;padding:0 12px}.psymod-account.psymod-account--auth{padding:0 12px}.psymod-account-card{padding:22px}.psymod-account-title{font-size:26px}.psymod-account-hero{padding:24px;flex-direction:column;align-items:flex-start}.psymod-account-hero h1{font-size:30px}.psymod-account-grid{grid-template-columns:1fr}.psymod-account-actions{flex-direction:column}.psymod-account-actions .psymod-account-button{width:100%}.psymod-account-footer{flex-direction:column;align-items:flex-start}}'
			. '@media (max-width:900px){.psymod-account-materials-grid{grid-template-columns:repeat(2,minmax(0,1fr));}}'
			. '@media (max-width:760px){.psymod-account-subscription-head{flex-direction:column;align-items:flex-start}.psymod-account-subscription-grid{grid-template-columns:1fr}}'
			. '@media (max-width:640px){.psymod-access-status-card{padding:16px}.psymod-access-status-title{font-size:22px}.psymod-account-materials-grid{grid-template-columns:1fr}}'
			. '</style>';
	}
}

if (! function_exists('psymod_account_get_library_post_type')) {
	/**
	 * Get existing PSYMOD Library post type slug.
	 */
	function psymod_account_get_library_post_type(): string
	{
		return defined('PSYMOD_LIBRARY_POST_TYPE') ? (string) PSYMOD_LIBRARY_POST_TYPE : 'psymod_material';
	}
}

if (! function_exists('psymod_account_get_allowed_material_access_levels')) {
	/**
	 * Get allowed material access levels.
	 *
	 * @return string[]
	 */
	function psymod_account_get_allowed_material_access_levels(): array
	{
		return array(
			PSYMOD_ACCESS_PUBLIC,
			PSYMOD_ACCESS_REGISTERED,
			PSYMOD_ACCESS_MEMBER,
			PSYMOD_ACCESS_PREMIUM,
			PSYMOD_ACCESS_ADMIN_ONLY,
		);
	}
}

if (! function_exists('psymod_account_get_access_label')) {
	/**
	 * Get human-readable access label.
	 */
	function psymod_account_get_access_label(string $level): string
	{
		$level = psymod_account_normalize_access_level($level);
		$map   = array(
			PSYMOD_ACCESS_PUBLIC     => 'Public',
			PSYMOD_ACCESS_REGISTERED => 'Free user',
			PSYMOD_ACCESS_MEMBER     => 'CORE',
			PSYMOD_ACCESS_PREMIUM    => 'PRO',
			PSYMOD_ACCESS_ADMIN_ONLY => 'Admin only',
		);

		return isset($map[$level]) ? $map[$level] : $map[PSYMOD_ACCESS_PUBLIC];
	}
}

if (! function_exists('psymod_account_get_managed_access_taxonomies')) {
	/**
	 * Get taxonomies where access term meta should be managed.
	 *
	 * @return string[]
	 */
	function psymod_account_get_managed_access_taxonomies(): array
	{
		$taxonomies = array('material_category');
		if (taxonomy_exists('material_section')) {
			$taxonomies[] = 'material_section';
		}

		return $taxonomies;
	}
}

if (! function_exists('psymod_account_get_term_access_level')) {
	/**
	 * Get validated access level for term meta.
	 */
	function psymod_account_get_term_access_level(int $term_id): string
	{
		static $cache = array();

		$term_id = absint($term_id);
		if ($term_id <= 0) {
			return PSYMOD_ACCESS_PUBLIC;
		}
		if (isset($cache[$term_id])) {
			return (string) $cache[$term_id];
		}

		$raw_value = sanitize_text_field((string) get_term_meta($term_id, 'required_access_level', true));
		if ($raw_value === '') {
			$raw_value = sanitize_text_field((string) get_term_meta($term_id, '_psymod_access_level', true));
		}
		$allowed   = psymod_account_get_allowed_material_access_levels();
		$normalized = in_array($raw_value, $allowed, true) ? $raw_value : PSYMOD_ACCESS_PUBLIC;
		$cache[$term_id] = $normalized;

		return $normalized;
	}
}

if (! function_exists('psymod_account_render_term_access_add_field')) {
	/**
	 * Render access field on taxonomy "Add term" screen.
	 */
	function psymod_account_render_term_access_add_field(string $taxonomy): void
	{
		$allowed = psymod_account_get_allowed_material_access_levels();
		?>
		<div class="form-field">
			<label for="psymod_account_term_access"><?php echo esc_html__('Уровень доступа', 'psymod-library'); ?></label>
			<select id="psymod_account_term_access" name="psymod_account_term_access">
				<?php foreach ($allowed as $level) : ?>
					<option value="<?php echo esc_attr($level); ?>"><?php echo esc_html(psymod_account_get_access_label($level)); ?></option>
				<?php endforeach; ?>
			</select>
			<p><?php echo esc_html__('Если у материала не задан индивидуальный доступ, он унаследует уровень доступа из категории.', 'psymod-library'); ?></p>
			<?php wp_nonce_field('psymod_account_save_term_access', 'psymod_account_term_access_nonce'); ?>
		</div>
		<?php
	}
}

if (! function_exists('psymod_account_render_term_access_edit_field')) {
	/**
	 * Render access field on taxonomy "Edit term" screen.
	 */
	function psymod_account_render_term_access_edit_field(WP_Term $term): void
	{
		$current = psymod_account_get_term_access_level((int) $term->term_id);
		$allowed = psymod_account_get_allowed_material_access_levels();
		?>
		<tr class="form-field">
			<th scope="row"><label for="psymod_account_term_access"><?php echo esc_html__('Уровень доступа', 'psymod-library'); ?></label></th>
			<td>
				<select id="psymod_account_term_access" name="psymod_account_term_access">
					<?php foreach ($allowed as $level) : ?>
						<option value="<?php echo esc_attr($level); ?>" <?php selected($current, $level); ?>>
							<?php echo esc_html(psymod_account_get_access_label($level)); ?>
						</option>
					<?php endforeach; ?>
				</select>
				<p class="description"><?php echo esc_html__('Если у материала не задан индивидуальный доступ, он унаследует уровень доступа из категории.', 'psymod-library'); ?></p>
				<?php wp_nonce_field('psymod_account_save_term_access', 'psymod_account_term_access_nonce'); ?>
			</td>
		</tr>
		<?php
	}
}

if (! function_exists('psymod_account_save_term_access_level')) {
	/**
	 * Save access level for taxonomy terms.
	 */
	function psymod_account_save_term_access_level(int $term_id): void
	{
		if (! current_user_can('manage_categories')) {
			return;
		}
		if (! isset($_POST['psymod_account_term_access_nonce'])) {
			return;
		}

		$nonce = sanitize_text_field(wp_unslash($_POST['psymod_account_term_access_nonce']));
		if (! wp_verify_nonce($nonce, 'psymod_account_save_term_access')) {
			return;
		}

		$raw_value = isset($_POST['psymod_account_term_access']) ? sanitize_text_field(wp_unslash($_POST['psymod_account_term_access'])) : PSYMOD_ACCESS_PUBLIC;
		$allowed   = psymod_account_get_allowed_material_access_levels();
		$value     = in_array($raw_value, $allowed, true) ? $raw_value : PSYMOD_ACCESS_PUBLIC;

		update_term_meta($term_id, 'required_access_level', $value);
	}
}

if (! function_exists('psymod_account_register_term_access_admin_hooks')) {
	/**
	 * Register taxonomy term access UI hooks.
	 */
	function psymod_account_register_term_access_admin_hooks(): void
	{
		foreach (psymod_account_get_managed_access_taxonomies() as $taxonomy) {
			add_action($taxonomy . '_add_form_fields', 'psymod_account_render_term_access_add_field');
			add_action($taxonomy . '_edit_form_fields', 'psymod_account_render_term_access_edit_field');
			add_action('created_' . $taxonomy, 'psymod_account_save_term_access_level');
			add_action('edited_' . $taxonomy, 'psymod_account_save_term_access_level');
		}
	}
}

if (! function_exists('psymod_account_add_term_access_column')) {
	/**
	 * Add Access column to managed taxonomies.
	 *
	 * @param array<string,string> $columns
	 * @return array<string,string>
	 */
	function psymod_account_add_term_access_column(array $columns): array
	{
		$columns['psymod_access'] = 'Access';
		return $columns;
	}
}

if (! function_exists('psymod_account_render_term_access_column')) {
	/**
	 * Render Access column value for taxonomy terms.
	 */
	function psymod_account_render_term_access_column(string $content, string $column_name, int $term_id): string
	{
		if ($column_name !== 'psymod_access') {
			return $content;
		}

		$level = psymod_account_get_term_access_level($term_id);
		return '<span style="display:inline-block;padding:2px 8px;border-radius:999px;background:#f3f4f6;border:1px solid #e5e7eb;font-size:12px;">' . esc_html(psymod_account_get_access_label($level)) . '</span>';
	}
}

if (! function_exists('psymod_account_register_term_access_columns_hooks')) {
	/**
	 * Register Access admin column hooks for managed taxonomies.
	 */
	function psymod_account_register_term_access_columns_hooks(): void
	{
		foreach (psymod_account_get_managed_access_taxonomies() as $taxonomy) {
			add_filter('manage_edit-' . $taxonomy . '_columns', 'psymod_account_add_term_access_column');
			add_filter('manage_' . $taxonomy . '_custom_column', 'psymod_account_render_term_access_column', 10, 3);
		}
	}
}

if (! function_exists('psymod_account_get_section_access_level')) {
	/**
	 * Get section-level access (filterable).
	 */
	function psymod_account_get_section_access_level(int $post_id): string
	{
		$post_type = get_post_type($post_id);
		$section   = '';
		$term_rank = psymod_account_get_access_rank(PSYMOD_ACCESS_PUBLIC);

		if ($post_type === psymod_account_get_library_post_type()) {
			$type_terms = get_the_terms($post_id, 'material_type');
			if (! is_wp_error($type_terms) && ! empty($type_terms)) {
				$first = reset($type_terms);
				if ($first instanceof WP_Term) {
					$section = (string) $first->slug;
				}
			}

			if (taxonomy_exists('material_section')) {
				$section_terms = get_the_terms($post_id, 'material_section');
				if (! is_wp_error($section_terms) && ! empty($section_terms)) {
					foreach ($section_terms as $term) {
						if (! $term instanceof WP_Term) {
							continue;
						}

						$to_check = array((int) $term->term_id);
						$anc      = get_ancestors((int) $term->term_id, 'material_section', 'taxonomy');
						foreach ($anc as $anc_id) {
							$to_check[] = (int) $anc_id;
						}

						foreach ($to_check as $term_id) {
							$rank = psymod_account_get_access_rank(psymod_account_get_term_access_level($term_id));
							if ($rank > $term_rank) {
								$term_rank = $rank;
							}
						}
					}
				}
			}
		}

		$default_map = array(
			'pro'      => PSYMOD_ACCESS_MEMBER,
			'scenario' => PSYMOD_ACCESS_MEMBER,
		);
		$level = isset($default_map[$section]) ? $default_map[$section] : PSYMOD_ACCESS_PUBLIC;
		$default_rank = psymod_account_get_access_rank($level);
		$effective_rank = $term_rank > $default_rank ? $term_rank : $default_rank;
		$hierarchy = psymod_account_get_access_hierarchy();
		$effective_level = isset($hierarchy[$effective_rank]) ? (string) $hierarchy[$effective_rank] : PSYMOD_ACCESS_PUBLIC;

		return psymod_account_normalize_access_level((string) apply_filters('psymod_account_section_access_level', $effective_level, $section, $post_id));
	}
}

if (! function_exists('psymod_account_get_category_inherited_access_level')) {
	/**
	 * Get strongest access level inherited from material categories and ancestors.
	 */
	function psymod_account_get_category_inherited_access_level(int $post_id): string
	{
		$terms = get_the_terms($post_id, 'material_category');
		if (is_wp_error($terms) || empty($terms)) {
			return PSYMOD_ACCESS_PUBLIC;
		}

		$max_rank = psymod_account_get_access_rank(PSYMOD_ACCESS_PUBLIC);
		foreach ($terms as $term) {
			if (! $term instanceof WP_Term) {
				continue;
			}

			$to_check = array((int) $term->term_id);
			$anc      = get_ancestors((int) $term->term_id, 'material_category', 'taxonomy');
			foreach ($anc as $anc_id) {
				$to_check[] = (int) $anc_id;
			}

			foreach ($to_check as $term_id) {
				$rank = psymod_account_get_access_rank(psymod_account_get_term_access_level($term_id));
				if ($rank > $max_rank) {
					$max_rank = $rank;
				}
			}
		}

		$hierarchy = psymod_account_get_access_hierarchy();
		return isset($hierarchy[$max_rank]) ? psymod_account_normalize_access_level((string) $hierarchy[$max_rank]) : PSYMOD_ACCESS_PUBLIC;
	}
}

if (! function_exists('psymod_account_register_material_access_metabox')) {
	/**
	 * Register material access level meta box.
	 */
	function psymod_account_register_material_access_metabox(): void
	{
		add_meta_box(
			'psymod_account_access_level',
			'Уровень доступа',
			'psymod_account_render_material_access_metabox',
			psymod_account_get_library_post_type(),
			'side',
			'default'
		);
	}
}

if (! function_exists('psymod_account_render_material_access_metabox')) {
	/**
	 * Render material access level meta box.
	 */
	function psymod_account_render_material_access_metabox(WP_Post $post): void
	{
		wp_nonce_field('psymod_account_save_material_access', 'psymod_account_material_access_nonce');

		$current = psymod_account_get_material_access_level((int) $post->ID);
		$options = array(
			PSYMOD_ACCESS_PUBLIC     => 'Public',
			PSYMOD_ACCESS_REGISTERED => 'Free user',
			PSYMOD_ACCESS_MEMBER     => 'CORE',
			PSYMOD_ACCESS_PREMIUM    => 'PRO',
			PSYMOD_ACCESS_ADMIN_ONLY => 'Admin only',
		);
		?>
		<p>
			<label for="psymod_account_access_level"><strong><?php echo esc_html__('Доступ к материалу', 'psymod-library'); ?></strong></label>
			<select id="psymod_account_access_level" name="psymod_account_access_level" style="width:100%;">
				<?php foreach ($options as $value => $label) : ?>
					<option value="<?php echo esc_attr($value); ?>" <?php selected($current, $value); ?>>
						<?php echo esc_html($label); ?>
					</option>
				<?php endforeach; ?>
			</select>
		</p>
		<?php
	}
}

if (! function_exists('psymod_account_save_material_access_level')) {
	/**
	 * Save material access level meta.
	 */
	function psymod_account_save_material_access_level(int $post_id): void
	{
		if (get_post_type($post_id) !== psymod_account_get_library_post_type()) {
			return;
		}

		if (! isset($_POST['psymod_account_material_access_nonce'])) {
			return;
		}
		$nonce = sanitize_text_field(wp_unslash($_POST['psymod_account_material_access_nonce']));
		if (! wp_verify_nonce($nonce, 'psymod_account_save_material_access')) {
			return;
		}
		if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
			return;
		}
		if (! current_user_can('edit_post', $post_id)) {
			return;
		}

		$raw_value = isset($_POST['psymod_account_access_level']) ? sanitize_text_field(wp_unslash($_POST['psymod_account_access_level'])) : PSYMOD_ACCESS_PUBLIC;
		$allowed   = psymod_account_get_allowed_material_access_levels();
		$value     = in_array($raw_value, $allowed, true) ? $raw_value : PSYMOD_ACCESS_PUBLIC;

		update_post_meta($post_id, 'required_access_level', $value);
	}
}

if (! function_exists('psymod_account_get_material_access_level')) {
	/**
	 * Get material access level from post meta.
	 */
	function psymod_account_get_material_access_level(int $post_id): string
	{
		static $cache = array();

		$post_id = absint($post_id);
		if ($post_id <= 0) {
			return PSYMOD_ACCESS_PUBLIC;
		}
		if (isset($cache[$post_id])) {
			return (string) $cache[$post_id];
		}

		$raw_value = sanitize_text_field((string) get_post_meta($post_id, 'required_access_level', true));
		if ($raw_value === '') {
			$raw_value = sanitize_text_field((string) get_post_meta($post_id, '_psymod_access_level', true));
		}
		if ($raw_value !== '') {
			$normalized      = psymod_account_normalize_access_level($raw_value);
			$cache[$post_id] = $normalized;
			return $normalized;
		}

		$section_level  = psymod_account_get_section_access_level($post_id);
		$category_level = psymod_account_get_category_inherited_access_level($post_id);
		$effective      = psymod_account_get_access_rank($category_level) > psymod_account_get_access_rank($section_level) ? $category_level : $section_level;

		$cache[$post_id] = $effective;
		return $effective;
	}
}

if (! function_exists('psymod_account_user_can_access_material')) {
	/**
	 * Check if current user can access material by its access level.
	 */
	function psymod_account_user_can_access_material(int $post_id): bool
	{
		$required = psymod_account_get_material_access_level($post_id);
		if ($required === PSYMOD_ACCESS_PUBLIC) {
			return true;
		}
		if ($required === PSYMOD_ACCESS_REGISTERED) {
			return is_user_logged_in();
		}
		if ($required === PSYMOD_ACCESS_MEMBER) {
			return psymod_account_user_has_minimum_access(PSYMOD_ACCESS_MEMBER);
		}
		if ($required === PSYMOD_ACCESS_PREMIUM) {
			return psymod_account_user_has_minimum_access(PSYMOD_ACCESS_PREMIUM);
		}
		if ($required === PSYMOD_ACCESS_ADMIN_ONLY) {
			return psymod_account_current_user_access_level() === 'admin';
		}

		return true;
	}
}

if (! function_exists('psymod_account_get_locked_block')) {
	/**
	 * Render locked block for restricted materials.
	 */
	function psymod_account_get_locked_block(string $required_level): string
	{
		$required_level = psymod_account_normalize_access_level($required_level);
		$text           = 'Этот материал доступен только участникам PSYMOD.';
		if ($required_level === PSYMOD_ACCESS_MEMBER) {
			$text = 'Требуется CORE доступ';
		} elseif ($required_level === PSYMOD_ACCESS_PREMIUM) {
			$text = 'Требуется PRO доступ';
		} elseif ($required_level === PSYMOD_ACCESS_ADMIN_ONLY) {
			$text = 'Материал доступен только администратору.';
		}

		ob_start();
		?>
		<div class="psymod-locked">
			<div class="psymod-locked-card">
				<div class="psymod-locked-icon" aria-hidden="true">🔒</div>
				<h3 class="psymod-locked-title"><?php echo esc_html__('Материал недоступен', 'psymod-library'); ?></h3>
				<p class="psymod-locked-text"><?php echo esc_html($text); ?></p>
				<div class="psymod-locked-actions">
					<a class="psymod-locked-button" href="<?php echo esc_url(home_url('/login/')); ?>"><?php echo esc_html__('Войти', 'psymod-library'); ?></a>
					<a class="psymod-locked-button is-secondary" href="<?php echo esc_url(home_url('/register/')); ?>"><?php echo esc_html__('Зарегистрироваться', 'psymod-library'); ?></a>
				</div>
			</div>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_get_query_mode')) {
	/**
	 * Get current access query mode.
	 *
	 * Modes: hide_locked|show_teaser|mixed
	 */
	function psymod_account_get_query_mode(): string
	{
		// MVP default: keep library cards visible for everyone (locked materials shown as badges/teasers).
		$mode = 'mixed';
		$mode = (string) apply_filters('psymod_account_access_mode', $mode);
		$allowed_modes = array('hide_locked', 'show_teaser', 'mixed');
		return in_array($mode, $allowed_modes, true) ? $mode : 'mixed';
	}
}

if (! function_exists('psymod_account_normalize_shortcode_limit')) {
	/**
	 * Normalize shortcode list limit with safe boundaries.
	 */
	function psymod_account_normalize_shortcode_limit($value, $default = 6, $max = 24): int
	{
		$default = max(1, absint($default));
		$max     = max($default, absint($max));
		$limit   = absint($value);
		if ($limit <= 0) {
			$limit = $default;
		}
		if ($limit > $max) {
			$limit = $max;
		}

		return $limit;
	}
}

if (! function_exists('psymod_account_get_accessible_levels_for_current_user')) {
	/**
	 * Get allowed material levels for current user (for meta query filtering).
	 *
	 * @return string[]
	 */
	function psymod_account_get_accessible_levels_for_current_user(): array
	{
		$current = psymod_account_current_user_access_level();
		if ($current === 'admin') {
			return array(
				PSYMOD_ACCESS_PUBLIC,
				PSYMOD_ACCESS_REGISTERED,
				PSYMOD_ACCESS_MEMBER,
				PSYMOD_ACCESS_PREMIUM,
				PSYMOD_ACCESS_ADMIN_ONLY,
			);
		}
		if ($current === PSYMOD_ACCESS_PREMIUM) {
			return array(
				PSYMOD_ACCESS_PUBLIC,
				PSYMOD_ACCESS_REGISTERED,
				PSYMOD_ACCESS_MEMBER,
				PSYMOD_ACCESS_PREMIUM,
			);
		}
		if ($current === PSYMOD_ACCESS_MEMBER) {
			return array(
				PSYMOD_ACCESS_PUBLIC,
				PSYMOD_ACCESS_REGISTERED,
				PSYMOD_ACCESS_MEMBER,
			);
		}
		if (is_user_logged_in()) {
			return array(
				PSYMOD_ACCESS_PUBLIC,
				PSYMOD_ACCESS_REGISTERED,
			);
		}
		return array(PSYMOD_ACCESS_PUBLIC);
	}
}

if (! function_exists('psymod_account_filter_library_query_by_access')) {
	/**
	 * Filter library queries by access mode and user permissions.
	 */
	function psymod_account_filter_library_query_by_access(WP_Query $query): void
	{
		// Temporary rollback: disable access query filtering to restore material visibility.
		return;

		if (is_admin()) {
			return;
		}

		$post_type = $query->get('post_type');
		$is_library_query = false;
		if (is_array($post_type)) {
			$is_library_query = in_array(psymod_account_get_library_post_type(), $post_type, true);
		} else {
			$is_library_query = $post_type === psymod_account_get_library_post_type();
		}
		if (! $is_library_query) {
			return;
		}

		// Never filter out singular material queries:
		// keep URL/title/breadcrumbs/routing alive and gate content later via the_content.
		$request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
		$path        = trim((string) wp_parse_url($request_uri, PHP_URL_PATH), '/');
		$is_library_path = strpos($path, 'library/') === 0;
		$is_library_non_single = strpos($path, '/category/') !== false
			|| strpos($path, '/type/') !== false
			|| strpos($path, '/section/') !== false
			|| $path === 'library';
		$is_custom_single_candidate = $is_library_path && ! $is_library_non_single;

		$is_single_candidate = $query->is_singular(psymod_account_get_library_post_type())
			|| is_singular(psymod_account_get_library_post_type())
			|| absint((string) $query->get('p')) > 0
			|| (string) $query->get('name') !== ''
			|| $is_custom_single_candidate;
		if ($is_single_candidate) {
			return;
		}

		$mode = psymod_account_get_query_mode();
		if ($mode !== 'hide_locked') {
			return;
		}

		$allowed_levels = psymod_account_get_accessible_levels_for_current_user();
		$meta_query     = $query->get('meta_query');
		if (! is_array($meta_query)) {
			$meta_query = array();
		}

		$meta_query[] = array(
			'relation' => 'OR',
			array(
				'key'     => 'required_access_level',
				'compare' => 'NOT EXISTS',
			),
			array(
				'key'     => 'required_access_level',
				'value'   => '',
				'compare' => '=',
			),
			array(
				'key'     => 'required_access_level',
				'value'   => $allowed_levels,
				'compare' => 'IN',
			),
		);

		$query->set('meta_query', $meta_query);
	}
}

if (! function_exists('psymod_account_get_preview_length')) {
	/**
	 * Get configurable teaser preview length.
	 */
	function psymod_account_get_preview_length(): int
	{
		$length = (int) apply_filters('psymod_account_preview_length', 280);
		return max(80, $length);
	}
}

if (! function_exists('psymod_account_get_teaser_block')) {
	/**
	 * Build teaser block for partially locked materials.
	 */
	function psymod_account_get_teaser_block(string $full_content, string $required_level): string
	{
		$plain = trim(wp_strip_all_tags($full_content));
		$teaser = mb_substr($plain, 0, psymod_account_get_preview_length());
		if (mb_strlen($plain) > mb_strlen($teaser)) {
			$teaser .= '...';
		}

		ob_start();
		?>
		<div class="psymod-locked">
			<div class="psymod-locked-card">
				<p class="psymod-locked-text"><?php echo esc_html($teaser); ?></p>
				<div style="margin:14px 0 0;padding:14px;border-radius:12px;background:linear-gradient(180deg,rgba(255,255,255,.1),#fff 55%);filter:blur(1.1px);opacity:.8;">
					<?php echo esc_html__('Продолжение материала доступно после получения доступа.', 'psymod-library'); ?>
				</div>
				<?php echo psymod_account_get_locked_block($required_level); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			</div>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_filter_single_material_content')) {
	/**
	 * Restrict single material content by account access rules.
	 */
	function psymod_account_filter_single_material_content(string $content): string
	{
		if (is_admin() || ! is_singular(psymod_account_get_library_post_type()) || ! in_the_loop() || ! is_main_query()) {
			return $content;
		}

		$post_id = get_the_ID();
		if (! $post_id) {
			return $content;
		}
		if (psymod_account_user_can_access_material((int) $post_id)) {
			$favorite_button = psymod_account_render_favorite_button((int) $post_id);
			if ($favorite_button === '') {
				return $content;
			}
			return $content . '<div class="psymod-account" style="max-width:960px;"><div class="psymod-account-card" style="margin-top:18px;">' . $favorite_button . '</div></div>';
		}

		$required_level = psymod_account_get_material_access_level((int) $post_id);
		$query_mode     = psymod_account_get_query_mode();
		$can_show_teaser = in_array($query_mode, array('show_teaser', 'mixed'), true)
			&& in_array($required_level, array(PSYMOD_ACCESS_MEMBER, PSYMOD_ACCESS_PREMIUM), true);

		ob_start();
		?>
		<div class="psymod-account psymod-account--auth">
			<div class="psymod-account-card">
				<h2 class="psymod-account-title"><?php echo esc_html(get_the_title((int) $post_id)); ?></h2>
				<?php if ($can_show_teaser) : ?>
					<?php echo psymod_account_get_teaser_block($content, $required_level); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				<?php else : ?>
					<?php echo psymod_account_get_locked_block($required_level); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				<?php endif; ?>
			</div>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_get_material_badge_html')) {
	/**
	 * Build access badge HTML for library cards.
	 */
	function psymod_account_get_material_badge_html(int $post_id): string
	{
		static $cache = array();
		if (isset($cache[$post_id])) {
			return (string) $cache[$post_id];
		}

		$required = psymod_account_get_material_access_level($post_id);
		if ($required === PSYMOD_ACCESS_REGISTERED) {
			$cache[$post_id] = '<span class="psymod-access-badge psymod-access-badge--registered" title="' . esc_attr__('Free user доступ', 'psymod-library') . '">' . esc_html('🔒 Free user') . '</span>';
			return (string) $cache[$post_id];
		}
		if ($required === PSYMOD_ACCESS_MEMBER) {
			$cache[$post_id] = '<span class="psymod-access-badge psymod-access-badge--member" title="' . esc_attr__('CORE доступ', 'psymod-library') . '">' . esc_html('🔒 CORE') . '</span>';
			return (string) $cache[$post_id];
		}
		if ($required === PSYMOD_ACCESS_PREMIUM) {
			$cache[$post_id] = '<span class="psymod-access-badge psymod-access-badge--premium" title="' . esc_attr__('PRO доступ', 'psymod-library') . '">' . esc_html('🔒 PRO') . '</span>';
			return (string) $cache[$post_id];
		}
		if ($required === PSYMOD_ACCESS_ADMIN_ONLY) {
			$cache[$post_id] = '<span class="psymod-access-badge psymod-access-badge--admin" title="' . esc_attr__('Admin only доступ', 'psymod-library') . '">' . esc_html('🔒 Admin') . '</span>';
			return (string) $cache[$post_id];
		}

		$cache[$post_id] = '';
		return '';
	}
}

if (! function_exists('psymod_account_render_access_aware_card_html')) {
	/**
	 * Prepare access-aware card HTML (bridge for future centralized renderer).
	 */
	function psymod_account_render_access_aware_card_html(string $article_html, int $post_id): string
	{
		$badge_html = psymod_account_get_material_badge_html($post_id);
		if ($badge_html === '') {
			return $article_html;
		}

		return preg_replace('/(<article class="psymod-material-card"[^>]*>)/', '$1' . $badge_html, $article_html, 1) ?: $article_html;
	}
}

if (! function_exists('psymod_account_inject_access_badges_into_library_cards')) {
	/**
	 * Inject access badges into rendered [psymod_library] cards.
	 */
	function psymod_account_inject_access_badges_into_library_cards(string $output, string $tag): string
	{
		if ($tag !== 'psymod_library' || $output === '') {
			return $output;
		}

		return (string) preg_replace_callback(
			'/<article class="psymod-material-card"[^>]*>.*?<\/article>/s',
			static function (array $matches): string {
				static $url_to_post_cache = array();

				$article_html = (string) $matches[0];
				if (! preg_match('/<a[^>]+href="([^"]+)"/', $article_html, $href_match)) {
					return $article_html;
				}

				$url = (string) $href_match[1];
				if (isset($url_to_post_cache[$url])) {
					$post_id = (int) $url_to_post_cache[$url];
				} else {
					$post_id = url_to_postid($url);
					$url_to_post_cache[$url] = $post_id;
				}

				if ($post_id <= 0) {
					return $article_html;
				}

				return psymod_account_render_access_aware_card_html($article_html, (int) $post_id);
			},
			$output
		);
	}
}

if (! function_exists('psymod_account_get_notice')) {
	/**
	 * Build account form notice from query params.
	 */
	function psymod_account_get_notice(): string
	{
		$error_key   = isset($_GET['psymod_error']) ? sanitize_text_field(wp_unslash($_GET['psymod_error'])) : '';
		$success_key = isset($_GET['psymod_success']) ? sanitize_text_field(wp_unslash($_GET['psymod_success'])) : '';

		$error_messages = array(
			'empty'             => 'Заполните все поля.',
			'invalid_email'     => 'Введите корректный email.',
			'email_exists'      => 'Пользователь с таким email уже существует.',
			'password_mismatch' => 'Пароли не совпадают.',
			'register_failed'   => 'Не удалось создать аккаунт.',
			'login_failed'      => 'Неверный логин или пароль.',
			'user_not_found'    => 'Пользователь с таким email не найден.',
			'reset_failed'      => 'Не удалось отправить письмо для восстановления пароля.',
		);

		$success_messages = array(
			'reset_sent' => 'Инструкция по восстановлению пароля отправлена на email.',
			'registered' => 'Регистрация прошла успешно.',
		);

		if ($error_key !== '' && isset($error_messages[$error_key])) {
			return '<p class="psymod-account-notice psymod-account-notice--error">' . esc_html($error_messages[$error_key]) . '</p>';
		}

		if ($success_key !== '' && isset($success_messages[$success_key])) {
			return '<p class="psymod-account-notice psymod-account-notice--success">' . esc_html($success_messages[$success_key]) . '</p>';
		}

		return '';
	}
}

if (! function_exists('psymod_account_handle_login')) {
	/**
	 * Handle login form POST.
	 */
	function psymod_account_handle_login(): void
	{
		if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
			return;
		}

		$action = isset($_POST['psymod_account_action']) ? sanitize_text_field(wp_unslash($_POST['psymod_account_action'])) : '';
		if ($action !== 'login') {
			return;
		}

		$login_page_url = home_url('/login/');
		$nonce          = isset($_POST['psymod_account_login_nonce']) ? sanitize_text_field(wp_unslash($_POST['psymod_account_login_nonce'])) : '';
		if ($nonce === '' || ! wp_verify_nonce($nonce, 'psymod_account_login')) {
			wp_safe_redirect(add_query_arg('psymod_error', 'login_failed', $login_page_url));
			exit;
		}

		$login_raw = isset($_POST['psymod_login']) ? sanitize_text_field(wp_unslash($_POST['psymod_login'])) : '';
		$password  = isset($_POST['psymod_password']) ? (string) wp_unslash($_POST['psymod_password']) : '';
		if ($login_raw === '' || $password === '') {
			wp_safe_redirect(add_query_arg('psymod_error', 'empty', $login_page_url));
			exit;
		}

		$user_login = $login_raw;
		if (is_email($login_raw)) {
			$user_by_email = get_user_by('email', $login_raw);
			if ($user_by_email instanceof WP_User) {
				$user_login = (string) $user_by_email->user_login;
			}
		}

		$user = wp_signon(
			array(
				'user_login'    => $user_login,
				'user_password' => $password,
				'remember'      => true,
			),
			is_ssl()
		);

		if (is_wp_error($user)) {
			wp_safe_redirect(add_query_arg('psymod_error', 'login_failed', $login_page_url));
			exit;
		}

		wp_safe_redirect(home_url('/account/'));
		exit;
	}
}

if (! function_exists('psymod_account_handle_register')) {
	/**
	 * Handle register form POST.
	 */
	function psymod_account_handle_register(): void
	{
		if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
			return;
		}

		$action = isset($_POST['psymod_account_action']) ? sanitize_text_field(wp_unslash($_POST['psymod_account_action'])) : '';
		if ($action !== 'register') {
			return;
		}

		$register_page_url = home_url('/register/');
		$posted_redirect   = isset($_POST['redirect_to']) ? (string) wp_unslash($_POST['redirect_to']) : '';
		$redirect_target   = '';
		if (function_exists('psymod_subscription_login_gate_get_safe_redirect_target_from_request')) {
			// Validate posted redirect_to against PSYMOD subscription products allow-list.
			$redirect_target = psymod_subscription_login_gate_get_safe_redirect_target_from_request();
		}
		if ($redirect_target === '' && $posted_redirect !== '') {
			$fallback = wp_validate_redirect($posted_redirect, '');
			if (is_string($fallback) && $fallback !== '') {
				$redirect_target = $fallback;
			}
		}
		$register_redirect_url = $register_page_url;
		if ($redirect_target !== '') {
			$register_redirect_url = add_query_arg('redirect_to', rawurlencode($redirect_target), $register_page_url);
		}
		$nonce             = isset($_POST['psymod_account_register_nonce']) ? sanitize_text_field(wp_unslash($_POST['psymod_account_register_nonce'])) : '';
		if ($nonce === '' || ! wp_verify_nonce($nonce, 'psymod_account_register')) {
			wp_safe_redirect(add_query_arg('psymod_error', 'register_failed', $register_redirect_url));
			exit;
		}

		$name            = isset($_POST['psymod_name']) ? sanitize_text_field(wp_unslash($_POST['psymod_name'])) : '';
		$email           = isset($_POST['psymod_email']) ? sanitize_email(wp_unslash($_POST['psymod_email'])) : '';
		$password        = isset($_POST['psymod_password']) ? (string) wp_unslash($_POST['psymod_password']) : '';
		$password_repeat = isset($_POST['psymod_password_repeat']) ? (string) wp_unslash($_POST['psymod_password_repeat']) : '';

		if ($name === '' || $email === '' || $password === '' || $password_repeat === '') {
			wp_safe_redirect(add_query_arg('psymod_error', 'empty', $register_redirect_url));
			exit;
		}

		if (! is_email($email)) {
			wp_safe_redirect(add_query_arg('psymod_error', 'invalid_email', $register_redirect_url));
			exit;
		}

		if (email_exists($email)) {
			wp_safe_redirect(add_query_arg('psymod_error', 'email_exists', $register_redirect_url));
			exit;
		}

		if ($password !== $password_repeat) {
			wp_safe_redirect(add_query_arg('psymod_error', 'password_mismatch', $register_redirect_url));
			exit;
		}

		$email_parts = explode('@', $email);
		$base_login  = sanitize_user((string) ($email_parts[0] ?? ''), true);
		if ($base_login === '') {
			$base_login = 'user';
		}

		$user_login = $base_login;
		if (username_exists($user_login)) {
			$user_login = $base_login . wp_generate_password(4, false);
		}
		for ($attempt = 0; $attempt < 5 && username_exists($user_login); $attempt++) {
			$user_login = $base_login . wp_generate_password(4, false);
		}

		$user_id = wp_create_user($user_login, $password, $email);
		if (is_wp_error($user_id) || ! $user_id) {
			wp_safe_redirect(add_query_arg('psymod_error', 'register_failed', $register_redirect_url));
			exit;
		}

		wp_update_user(
			array(
				'ID'           => (int) $user_id,
				'display_name' => $name,
			)
		);

		$user = get_user_by('id', (int) $user_id);
		if ($user instanceof WP_User) {
			$user->set_role('psymod_free');
		}

		$signon = wp_signon(
			array(
				'user_login'    => $user_login,
				'user_password' => $password,
				'remember'      => true,
			),
			is_ssl()
		);

		if (is_wp_error($signon)) {
			wp_safe_redirect(add_query_arg('psymod_error', 'login_failed', home_url('/login/')));
			exit;
		}

		$final_redirect = $redirect_target !== '' ? $redirect_target : home_url('/account/');
		wp_safe_redirect(add_query_arg('psymod_success', 'registered', $final_redirect));
		exit;
	}
}

if (! function_exists('psymod_account_handle_reset_password')) {
	/**
	 * Handle reset password form POST.
	 */
	function psymod_account_handle_reset_password(): void
	{
		if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
			return;
		}

		$action = isset($_POST['psymod_account_action']) ? sanitize_text_field(wp_unslash($_POST['psymod_account_action'])) : '';
		if ($action !== 'reset_password') {
			return;
		}

		$reset_page_url = home_url('/reset-password/');
		$nonce          = isset($_POST['psymod_account_reset_nonce']) ? sanitize_text_field(wp_unslash($_POST['psymod_account_reset_nonce'])) : '';
		if ($nonce === '' || ! wp_verify_nonce($nonce, 'psymod_account_reset_password')) {
			wp_safe_redirect(add_query_arg('psymod_error', 'reset_failed', $reset_page_url));
			exit;
		}

		$email = isset($_POST['psymod_reset_email']) ? sanitize_email(wp_unslash($_POST['psymod_reset_email'])) : '';
		if ($email === '') {
			wp_safe_redirect(add_query_arg('psymod_error', 'empty', $reset_page_url));
			exit;
		}

		if (! is_email($email)) {
			wp_safe_redirect(add_query_arg('psymod_error', 'invalid_email', $reset_page_url));
			exit;
		}

		$user = get_user_by('email', $email);
		if (! ($user instanceof WP_User)) {
			wp_safe_redirect(add_query_arg('psymod_error', 'user_not_found', $reset_page_url));
			exit;
		}

		$result = retrieve_password((string) $user->user_login);
		if (is_wp_error($result)) {
			wp_safe_redirect(add_query_arg('psymod_error', 'reset_failed', $reset_page_url));
			exit;
		}

		wp_safe_redirect(add_query_arg('psymod_success', 'reset_sent', $reset_page_url));
		exit;
	}
}

if (! function_exists('psymod_account_login_shortcode')) {
	/**
	 * Shortcode [psymod_login].
	 */
	function psymod_account_login_shortcode(): string
	{
		$account_url = home_url('/account/');
		$login_url   = home_url('/login/');

		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		?>
		<div class="psymod-account psymod-account--auth">
			<div class="psymod-account-card">
				<h2 class="psymod-account-title"><?php echo esc_html__('Вход', 'psymod-library'); ?></h2>
				<?php echo psymod_account_get_notice(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				<?php if (is_user_logged_in()) : ?>
					<p class="psymod-account-notice"><?php echo esc_html__('Вы уже вошли в систему.', 'psymod-library'); ?></p>
					<div class="psymod-account-actions">
						<a class="psymod-account-button" href="<?php echo esc_url($account_url); ?>"><?php echo esc_html__('Перейти в кабинет', 'psymod-library'); ?></a>
					</div>
				<?php else : ?>
					<form class="psymod-account-form" method="post" action="<?php echo esc_url($login_url); ?>">
						<input type="hidden" name="psymod_account_action" value="login">
						<?php wp_nonce_field('psymod_account_login', 'psymod_account_login_nonce'); ?>
						<label class="psymod-account-field">
							<span><?php echo esc_html__('Email или имя пользователя', 'psymod-library'); ?></span>
							<input class="psymod-account-input" type="text" name="psymod_login" required>
						</label>
						<label class="psymod-account-field">
							<span><?php echo esc_html__('Пароль', 'psymod-library'); ?></span>
							<input class="psymod-account-input" type="password" name="psymod_password" required>
						</label>
						<button class="psymod-account-button" type="submit"><?php echo esc_html__('Войти', 'psymod-library'); ?></button>
					</form>
					<div class="psymod-account-footer">
						<a class="psymod-account-link" href="<?php echo esc_url(home_url('/reset-password/')); ?>"><?php echo esc_html__('Забыли пароль?', 'psymod-library'); ?></a>
						<a class="psymod-account-link" href="<?php echo esc_url(home_url('/register/')); ?>"><?php echo esc_html__('Создать аккаунт', 'psymod-library'); ?></a>
					</div>
				<?php endif; ?>
			</div>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_register_shortcode')) {
	/**
	 * Shortcode [psymod_register].
	 */
	function psymod_account_register_shortcode(): string
	{
		$account_url = home_url('/account/');
		$redirect_to = '';
		if (function_exists('psymod_subscription_login_gate_get_safe_redirect_target_from_request')) {
			$redirect_to = psymod_subscription_login_gate_get_safe_redirect_target_from_request();
		}

		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		?>
		<div class="psymod-account psymod-account--auth">
			<div class="psymod-account-card">
				<h2 class="psymod-account-title"><?php echo esc_html__('Регистрация', 'psymod-library'); ?></h2>
				<?php echo psymod_account_get_notice(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				<?php if (is_user_logged_in()) : ?>
					<p class="psymod-account-notice"><?php echo esc_html__('Вы уже зарегистрированы.', 'psymod-library'); ?></p>
					<div class="psymod-account-actions">
						<a class="psymod-account-button" href="<?php echo esc_url($account_url); ?>"><?php echo esc_html__('Перейти в кабинет', 'psymod-library'); ?></a>
					</div>
				<?php else : ?>
					<form class="psymod-account-form" method="post" action="<?php echo esc_url(home_url('/register/')); ?>">
						<input type="hidden" name="psymod_account_action" value="register">
						<?php if ($redirect_to !== '') : ?>
							<input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>">
						<?php endif; ?>
						<?php wp_nonce_field('psymod_account_register', 'psymod_account_register_nonce'); ?>
						<label class="psymod-account-field">
							<span><?php echo esc_html__('Имя', 'psymod-library'); ?></span>
							<input class="psymod-account-input" type="text" name="psymod_name" required>
						</label>
						<label class="psymod-account-field">
							<span><?php echo esc_html__('Email', 'psymod-library'); ?></span>
							<input class="psymod-account-input" type="email" name="psymod_email" required>
						</label>
						<label class="psymod-account-field">
							<span><?php echo esc_html__('Пароль', 'psymod-library'); ?></span>
							<input class="psymod-account-input" type="password" name="psymod_password" required>
						</label>
						<label class="psymod-account-field">
							<span><?php echo esc_html__('Повторите пароль', 'psymod-library'); ?></span>
							<input class="psymod-account-input" type="password" name="psymod_password_repeat" required>
						</label>
						<button class="psymod-account-button" type="submit"><?php echo esc_html__('Зарегистрироваться', 'psymod-library'); ?></button>
					</form>
					<div class="psymod-account-footer">
						<?php
						$login_url = home_url('/login/');
						if ($redirect_to !== '') {
							$login_url = add_query_arg('redirect_to', rawurlencode($redirect_to), $login_url);
						}
						?>
						<a class="psymod-account-link" href="<?php echo esc_url($login_url); ?>"><?php echo esc_html__('Уже есть аккаунт? Войти', 'psymod-library'); ?></a>
					</div>
				<?php endif; ?>
			</div>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_reset_password_shortcode')) {
	/**
	 * Shortcode [psymod_reset_password].
	 */
	function psymod_account_reset_password_shortcode(): string
	{
		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		?>
		<div class="psymod-account psymod-account--auth">
			<div class="psymod-account-card">
				<h2 class="psymod-account-title"><?php echo esc_html__('Восстановление пароля', 'psymod-library'); ?></h2>
				<?php echo psymod_account_get_notice(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				<form class="psymod-account-form" method="post" action="<?php echo esc_url(home_url('/reset-password/')); ?>">
					<input type="hidden" name="psymod_account_action" value="reset_password">
					<?php wp_nonce_field('psymod_account_reset_password', 'psymod_account_reset_nonce'); ?>
					<label class="psymod-account-field">
						<span><?php echo esc_html__('Email', 'psymod-library'); ?></span>
						<input class="psymod-account-input" type="email" name="psymod_reset_email" required>
					</label>
					<button class="psymod-account-button" type="submit"><?php echo esc_html__('Восстановить пароль', 'psymod-library'); ?></button>
				</form>
				<div class="psymod-account-footer">
					<a class="psymod-account-link" href="<?php echo esc_url(home_url('/login/')); ?>"><?php echo esc_html__('Вернуться ко входу', 'psymod-library'); ?></a>
				</div>
			</div>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_render_user_access_status')) {
	/**
	 * Render user access/subscription status block.
	 */
	function psymod_account_render_user_access_status(): string
	{
		$is_logged_in = is_user_logged_in();
		$raw_level    = psymod_account_current_user_access_level();
		$status_level = $is_logged_in ? $raw_level : 'guest';

		$title       = 'Статус доступа';
		$level_label = 'Guest';
		$text        = 'Войдите или зарегистрируйтесь, чтобы получить больше материалов';
		$actions     = array(
			array('label' => 'Войти', 'url' => home_url('/login/')),
			array('label' => 'Зарегистрироваться', 'url' => home_url('/register/')),
		);

		if ($status_level === PSYMOD_ACCESS_REGISTERED) {
			$level_label = 'Free user';
			$text        = 'Вам доступны публичные и зарегистрированные материалы';
			$actions     = array(
				array('label' => 'Выбрать подписку', 'url' => home_url('/podpiski/')),
			);
		} elseif ($status_level === PSYMOD_ACCESS_MEMBER) {
			$level_label = 'CORE';
			$text        = 'Вам доступны CORE материалы';
			$actions     = array(
				array('label' => 'Перейти в библиотеку', 'url' => home_url('/library/')),
			);
		} elseif ($status_level === PSYMOD_ACCESS_PREMIUM) {
			$level_label = 'PRO';
			$text        = 'Вам доступны PRO материалы';
			$actions     = array(
				array('label' => 'Перейти в библиотеку', 'url' => home_url('/library/')),
			);
		} elseif ($status_level === 'admin') {
			$level_label = 'Admin';
			$text        = 'Вам доступны все материалы библиотеки.';
			$actions     = array();
		}

		ob_start();
		?>
		<section class="psymod-access-status">
			<div class="psymod-access-status-card">
				<h3 class="psymod-access-status-title"><?php echo esc_html($title); ?></h3>
				<div class="psymod-access-status-level"><?php echo esc_html($level_label); ?></div>
				<p class="psymod-account-notice"><?php echo esc_html($text); ?></p>
				<?php if (! empty($actions)) : ?>
					<div class="psymod-account-actions">
						<?php foreach ($actions as $action) : ?>
							<a class="psymod-account-cta" href="<?php echo esc_url((string) $action['url']); ?>"><?php echo esc_html((string) $action['label']); ?></a>
						<?php endforeach; ?>
					</div>
				<?php endif; ?>
			</div>
		</section>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_get_material_excerpt_text')) {
	/**
	 * Build safe short excerpt for account dashboard cards.
	 */
	function psymod_account_get_material_excerpt_text(int $post_id): string
	{
		$excerpt = trim((string) get_post_field('post_excerpt', $post_id));
		if ($excerpt === '') {
			$excerpt = trim((string) get_post_field('post_content', $post_id));
		}

		return wp_trim_words(wp_strip_all_tags($excerpt), 20, '...');
	}
}

if (! function_exists('psymod_account_get_user_primary_subscription')) {
	/**
	 * Get highest-priority subscription for current user (active first).
	 */
	function psymod_account_get_user_primary_subscription(int $user_id = 0)
	{
		$user_id = absint($user_id);
		if ($user_id <= 0 || ! function_exists('wcs_get_users_subscriptions')) {
			return null;
		}

		$subscriptions = wcs_get_users_subscriptions($user_id);
		if (! is_array($subscriptions) || empty($subscriptions)) {
			return null;
		}

		$active = null;
		$fallback = null;
		foreach ($subscriptions as $subscription) {
			if (! is_object($subscription) || ! method_exists($subscription, 'get_id')) {
				continue;
			}

			if ($fallback === null) {
				$fallback = $subscription;
			}

			if (method_exists($subscription, 'has_status') && $subscription->has_status('active')) {
				$active = $subscription;
				break;
			}
		}

		return $active ?: $fallback;
	}
}

if (! function_exists('psymod_account_get_subscription_access_label')) {
	/**
	 * Resolve CORE/PRO access label by subscription items.
	 */
	function psymod_account_get_subscription_access_label($subscription): string
	{
		if (! is_object($subscription) || ! method_exists($subscription, 'get_items')) {
			return '';
		}

		$has_core = false;
		foreach ($subscription->get_items() as $item) {
			if (! is_object($item) || ! method_exists($item, 'get_product_id')) {
				continue;
			}

			$product_id = absint($item->get_product_id());
			$variation_id = method_exists($item, 'get_variation_id') ? absint($item->get_variation_id()) : 0;
			$product_name = method_exists($item, 'get_name') ? sanitize_text_field((string) $item->get_name()) : '';

			$level = '';
			if (function_exists('psymod_subscription_access_detect_level_by_product')) {
				$level = psymod_subscription_access_detect_level_by_product($product_id, $product_name);
				if ($level === '' && $variation_id > 0) {
					$level = psymod_subscription_access_detect_level_by_product($variation_id, $product_name);
				}
			}

			if ($level === '') {
				$key = strtolower(trim($product_name));
				if (strpos($key, 'pro') !== false) {
					$level = 'pro';
				} elseif (strpos($key, 'core') !== false) {
					$level = 'core';
				}
			}

			if ($level === 'pro') {
				return 'PRO';
			}
			if ($level === 'core') {
				$has_core = true;
			}
		}

		return $has_core ? 'CORE' : '';
	}
}

if (! function_exists('psymod_account_get_subscription_cancel_url')) {
	/**
	 * Get safe cancel URL from WooCommerce Subscriptions actions.
	 */
	function psymod_account_get_subscription_cancel_url($subscription, int $user_id): string
	{
		$user_id = absint($user_id);
		if (! is_object($subscription) || $user_id <= 0) {
			return '';
		}

		if (function_exists('wcs_get_all_user_actions_for_subscription')) {
			$actions = wcs_get_all_user_actions_for_subscription($subscription, $user_id);
			if (is_array($actions) && isset($actions['cancel']['url'])) {
				return esc_url_raw((string) $actions['cancel']['url']);
			}
		}

		if (method_exists($subscription, 'get_cancel_url')) {
			return esc_url_raw((string) $subscription->get_cancel_url());
		}

		if (method_exists($subscription, 'get_change_status_link')) {
			return esc_url_raw((string) $subscription->get_change_status_link('cancel'));
		}

		return '';
	}
}

if (! function_exists('psymod_account_get_subscription_reactivate_url')) {
	/**
	 * Get safe reactivate URL from WooCommerce Subscriptions actions.
	 */
	function psymod_account_get_subscription_reactivate_url($subscription, int $user_id): string
	{
		$user_id = absint($user_id);
		if (! is_object($subscription) || $user_id <= 0) {
			return '';
		}

		if (function_exists('wcs_get_all_user_actions_for_subscription')) {
			$actions = wcs_get_all_user_actions_for_subscription($subscription, $user_id);
			if (is_array($actions) && ! empty($actions)) {
				$preferred_keys = array('reactivate', 'resubscribe', 'renew');
				foreach ($preferred_keys as $key) {
					if (isset($actions[$key]['url']) && (string) $actions[$key]['url'] !== '') {
						return esc_url_raw((string) $actions[$key]['url']);
					}
				}

				foreach ($actions as $action_key => $action_data) {
					$action_key = strtolower(sanitize_key((string) $action_key));
					if (! is_array($action_data)) {
						continue;
					}

					$haystack = $action_key . ' ';
					if (isset($action_data['name'])) {
						$haystack .= strtolower((string) $action_data['name']) . ' ';
					}
					if (isset($action_data['title'])) {
						$haystack .= strtolower((string) $action_data['title']) . ' ';
					}

					$matches_reactivate = strpos($haystack, 'reactivate') !== false || strpos($haystack, 'возобнов') !== false;
					$matches_resubscribe = strpos($haystack, 'resubscribe') !== false;
					$matches_renew = strpos($haystack, 'renew') !== false;

					if (($matches_reactivate || $matches_resubscribe || $matches_renew) && isset($action_data['url']) && (string) $action_data['url'] !== '') {
						return esc_url_raw((string) $action_data['url']);
					}
				}
			}
		}

		return '';
	}
}

if (! function_exists('psymod_account_get_subscription_access_until')) {
	/**
	 * Resolve access-until info for cancelled/pending-cancel subscriptions.
	 *
	 * @return array{has_future:bool,date:string}
	 */
	function psymod_account_get_subscription_access_until($subscription): array
	{
		if (! is_object($subscription)) {
			return array('has_future' => false, 'date' => '');
		}

		$timestamp = 0;
		if (method_exists($subscription, 'get_time')) {
			$timestamp = absint($subscription->get_time('end'));
			if ($timestamp <= 0) {
				$timestamp = absint($subscription->get_time('next_payment'));
			}
		}

		$display_date = '';
		if ($timestamp > 0) {
			$display_date = wp_date(get_option('date_format'), $timestamp);
		}

		if ($display_date === '' && method_exists($subscription, 'get_date_to_display')) {
			$display_date = (string) $subscription->get_date_to_display('end');
			if ($display_date === '') {
				$display_date = (string) $subscription->get_date_to_display('next_payment');
			}
		}

		$has_future = $timestamp > current_time('timestamp');
		if (! $has_future && $timestamp <= 0) {
			// If precise timestamp is unavailable but date exists, treat as paid period info available.
			$has_future = $display_date !== '';
		}

		return array(
			'has_future' => $has_future,
			'date'       => sanitize_text_field($display_date),
		);
	}
}

if (! function_exists('psymod_account_render_my_subscription_panel')) {
	/**
	 * Render "My Subscription" panel for current user.
	 */
	function psymod_account_render_my_subscription_panel(): string
	{
		$user = wp_get_current_user();
		if (! ($user instanceof WP_User) || ! $user->exists()) {
			return '';
		}

		$user_id = (int) $user->ID;
		$library_url = home_url('/library/');
		$plans_url = home_url('/podpiski/');
		$subscription = psymod_account_get_user_primary_subscription($user_id);

		ob_start();
		?>
		<section class="psymod-account-subscription">
			<div class="psymod-account-subscription-card">
				<?php if (! is_object($subscription)) : ?>
					<div class="psymod-account-subscription-head">
						<h3 class="psymod-account-subscription-title"><?php echo esc_html__('Моя подписка', 'psymod-library'); ?></h3>
					</div>
					<p class="psymod-account-subscription-empty"><?php echo esc_html__('У вас пока нет активной подписки', 'psymod-library'); ?></p>
					<div class="psymod-account-subscription-actions">
						<a class="psymod-account-button psymod-account-button--primary" href="<?php echo esc_url($plans_url); ?>">
							<?php echo esc_html__('Выбрать подписку', 'psymod-library'); ?>
						</a>
					</div>
				<?php else : ?>
					<?php
					$status_slug = method_exists($subscription, 'get_status') ? sanitize_title((string) $subscription->get_status()) : '';
					$status_name = function_exists('wcs_get_subscription_status_name') ? wcs_get_subscription_status_name($status_slug) : ucfirst($status_slug);
					$next_payment = method_exists($subscription, 'get_date_to_display') ? (string) $subscription->get_date_to_display('next_payment') : '';
					$price = method_exists($subscription, 'get_formatted_order_total') ? (string) $subscription->get_formatted_order_total() : '';
					$cancel_url = psymod_account_get_subscription_cancel_url($subscription, $user_id);
					$reactivate_url = psymod_account_get_subscription_reactivate_url($subscription, $user_id);
					$access_until = psymod_account_get_subscription_access_until($subscription);
					$items = method_exists($subscription, 'get_items') ? $subscription->get_items() : array();
					$item_title = '';
					foreach ($items as $item) {
						if (is_object($item) && method_exists($item, 'get_name')) {
							$item_title = sanitize_text_field((string) $item->get_name());
							if ($item_title !== '') {
								break;
							}
						}
					}
					$access_label = psymod_account_get_subscription_access_label($subscription);
					$can_show_cancel = $status_slug === 'active' && $cancel_url !== '';
					$has_paid_period = in_array($status_slug, array('pending-cancel', 'cancelled'), true) && ! empty($access_until['has_future']);
					$is_pending_cancel = $status_slug === 'pending-cancel' && $has_paid_period;
					$can_open_library = $status_slug === 'active' || $has_paid_period;
					?>
					<div class="psymod-account-subscription-head">
						<h3 class="psymod-account-subscription-title"><?php echo esc_html__('Моя подписка', 'psymod-library'); ?></h3>
						<span class="psymod-account-subscription-status status-<?php echo esc_attr($status_slug); ?>"><?php echo esc_html($status_name !== '' ? $status_name : __('Unknown', 'psymod-library')); ?></span>
					</div>

					<div class="psymod-account-subscription-grid">
						<p class="psymod-account-subscription-item">
							<span class="psymod-account-subscription-label"><?php echo esc_html__('Тариф', 'psymod-library'); ?></span>
							<span class="psymod-account-subscription-value"><?php echo esc_html($item_title !== '' ? $item_title : __('Подписка', 'psymod-library')); ?></span>
						</p>
						<p class="psymod-account-subscription-item">
							<span class="psymod-account-subscription-label"><?php echo esc_html__('Уровень доступа', 'psymod-library'); ?></span>
							<span class="psymod-account-subscription-value"><?php echo esc_html($access_label !== '' ? $access_label : '—'); ?></span>
						</p>
						<p class="psymod-account-subscription-item">
							<span class="psymod-account-subscription-label"><?php echo esc_html__('Цена', 'psymod-library'); ?></span>
							<span class="psymod-account-subscription-value"><?php echo esc_html($price !== '' ? wp_strip_all_tags($price) : '—'); ?></span>
						</p>
						<p class="psymod-account-subscription-item">
							<span class="psymod-account-subscription-label"><?php echo esc_html__('Следующее списание', 'psymod-library'); ?></span>
							<span class="psymod-account-subscription-value"><?php echo esc_html($next_payment !== '' ? $next_payment : __('Не запланировано', 'psymod-library')); ?></span>
						</p>
					</div>

					<div class="psymod-account-subscription-actions">
						<?php if ($can_open_library) : ?>
							<a class="psymod-account-button psymod-account-button--primary" href="<?php echo esc_url($library_url); ?>">
								<?php echo esc_html__('Перейти в библиотеку', 'psymod-library'); ?>
							</a>
						<?php else : ?>
							<a class="psymod-account-button psymod-account-button--primary" href="<?php echo esc_url($plans_url); ?>">
								<?php echo esc_html__('Выбрать подписку', 'psymod-library'); ?>
							</a>
						<?php endif; ?>
						<?php if ($can_show_cancel) : ?>
							<a class="psymod-account-button psymod-account-btn--danger" href="<?php echo esc_url($cancel_url); ?>">
								<?php echo esc_html__('Отменить подписку', 'psymod-library'); ?>
							</a>
						<?php elseif ($is_pending_cancel && $reactivate_url !== '') : ?>
							<a class="psymod-account-button psymod-account-btn--reactivate" href="<?php echo esc_url($reactivate_url); ?>">
								<?php echo esc_html__('Возобновить подписку', 'psymod-library'); ?>
							</a>
						<?php elseif ($is_pending_cancel) : ?>
							<a class="psymod-account-button psymod-account-button--secondary" href="<?php echo esc_url($plans_url); ?>">
								<?php echo esc_html__('Выбрать подписку', 'psymod-library'); ?>
							</a>
						<?php elseif ($reactivate_url !== '' && in_array($status_slug, array('cancelled', 'on-hold', 'expired'), true) && $can_open_library) : ?>
							<a class="psymod-account-button psymod-account-btn--reactivate" href="<?php echo esc_url($reactivate_url); ?>">
								<?php echo esc_html__('Возобновить подписку', 'psymod-library'); ?>
							</a>
						<?php endif; ?>
					</div>
					<?php if ($has_paid_period) : ?>
						<p class="psymod-account-subscription-note">
							<?php
							if (! empty($access_until['date'])) {
								echo esc_html(sprintf(__('Подписка отменена. Доступ сохранится до: %s', 'psymod-library'), (string) $access_until['date']));
							} else {
								echo esc_html__('Подписка отменена. Доступ сохранится до конца оплаченного периода.', 'psymod-library');
							}
							?>
						</p>
					<?php elseif (! $can_show_cancel && $status_slug === 'active') : ?>
						<p class="psymod-account-subscription-note"><?php echo esc_html__('Управление отменой недоступно для текущего статуса подписки.', 'psymod-library'); ?></p>
					<?php endif; ?>
				<?php endif; ?>
			</div>
		</section>
		<?php

		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_my_subscription_shortcode')) {
	/**
	 * Shortcode [psymod_my_subscription].
	 */
	function psymod_account_my_subscription_shortcode(): string
	{
		if (! is_user_logged_in()) {
			return '';
		}

		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo psymod_account_render_my_subscription_panel(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_get_target_user_id')) {
	/**
	 * Resolve target user id (fallback to current user).
	 */
	function psymod_account_get_target_user_id($user_id = 0): int
	{
		$user_id = absint($user_id);
		if ($user_id > 0) {
			return $user_id;
		}

		$current_user = wp_get_current_user();
		return $current_user instanceof WP_User ? (int) $current_user->ID : 0;
	}
}

if (! function_exists('psymod_account_get_user_favorites')) {
	/**
	 * Get favorite materials list from user meta.
	 *
	 * @return int[]
	 */
	function psymod_account_get_user_favorites($user_id = 0): array
	{
		static $cache = array();

		$user_id = psymod_account_get_target_user_id($user_id);
		if ($user_id <= 0) {
			return array();
		}
		if (isset($cache[$user_id])) {
			return (array) $cache[$user_id];
		}

		$raw = get_user_meta($user_id, '_psymod_favorite_materials', true);
		if (! is_array($raw)) {
			$raw = array();
		}

		$post_type = psymod_account_get_library_post_type();
		$ids = array();
		foreach ($raw as $item) {
			$post_id = absint($item);
			if ($post_id <= 0) {
				continue;
			}
			if (get_post_type($post_id) !== $post_type) {
				continue;
			}
			$ids[] = $post_id;
		}

		$cache[$user_id] = array_values(array_unique($ids));
		return (array) $cache[$user_id];
	}
}

if (! function_exists('psymod_account_is_material_favorite')) {
	/**
	 * Check if material is in favorites.
	 */
	function psymod_account_is_material_favorite($post_id, $user_id = 0): bool
	{
		$post_id = absint($post_id);
		if ($post_id <= 0) {
			return false;
		}
		$favorites = psymod_account_get_user_favorites($user_id);
		return in_array($post_id, $favorites, true);
	}
}

if (! function_exists('psymod_account_add_material_to_favorites')) {
	/**
	 * Add material to favorites.
	 */
	function psymod_account_add_material_to_favorites($post_id, $user_id = 0): bool
	{
		$user_id = psymod_account_get_target_user_id($user_id);
		$post_id = absint($post_id);
		if ($user_id <= 0 || $post_id <= 0 || ! is_user_logged_in()) {
			return false;
		}
		if (get_post_type($post_id) !== psymod_account_get_library_post_type()) {
			return false;
		}

		$favorites = psymod_account_get_user_favorites($user_id);
		if (! in_array($post_id, $favorites, true)) {
			array_unshift($favorites, $post_id);
		}
		$favorites = array_slice(array_values(array_unique(array_map('absint', $favorites))), 0, 100);
		update_user_meta($user_id, '_psymod_favorite_materials', $favorites);
		return true;
	}
}

if (! function_exists('psymod_account_remove_material_from_favorites')) {
	/**
	 * Remove material from favorites.
	 */
	function psymod_account_remove_material_from_favorites($post_id, $user_id = 0): bool
	{
		$user_id = psymod_account_get_target_user_id($user_id);
		$post_id = absint($post_id);
		if ($user_id <= 0 || $post_id <= 0 || ! is_user_logged_in()) {
			return false;
		}

		$favorites = psymod_account_get_user_favorites($user_id);
		$favorites = array_values(array_filter($favorites, static function (int $id) use ($post_id): bool {
			return $id !== $post_id;
		}));

		update_user_meta($user_id, '_psymod_favorite_materials', $favorites);
		return true;
	}
}

if (! function_exists('psymod_account_toggle_material_favorite')) {
	/**
	 * Toggle material favorite status.
	 */
	function psymod_account_toggle_material_favorite($post_id, $user_id = 0): bool
	{
		$post_id = absint($post_id);
		if ($post_id <= 0) {
			return false;
		}

		if (psymod_account_is_material_favorite($post_id, $user_id)) {
			return psymod_account_remove_material_from_favorites($post_id, $user_id);
		}

		return psymod_account_add_material_to_favorites($post_id, $user_id);
	}
}

if (! function_exists('psymod_account_render_favorite_button')) {
	/**
	 * Render favorite toggle button.
	 */
	function psymod_account_render_favorite_button($post_id = 0): string
	{
		if (! is_user_logged_in()) {
			return '';
		}

		$post_id = absint($post_id);
		if ($post_id <= 0) {
			$post_id = absint(get_the_ID());
		}
		if ($post_id <= 0 || get_post_type($post_id) !== psymod_account_get_library_post_type()) {
			return '';
		}

		$is_favorite = psymod_account_is_material_favorite($post_id);
		$label       = $is_favorite ? 'Убрать из избранного' : 'Добавить в избранное';
		$btn_class   = 'psymod-favorite-button' . ($is_favorite ? ' psymod-favorite-button--active' : '');
		$redirect_to = add_query_arg(array());

		ob_start();
		?>
		<form method="post" action="<?php echo esc_url($redirect_to); ?>" class="psymod-account-actions">
			<input type="hidden" name="psymod_account_action" value="toggle_favorite">
			<input type="hidden" name="psymod_post_id" value="<?php echo esc_attr((string) $post_id); ?>">
			<input type="hidden" name="psymod_redirect_to" value="<?php echo esc_url($redirect_to); ?>">
			<?php wp_nonce_field('psymod_account_favorite_action', 'psymod_account_favorite_nonce'); ?>
			<button class="<?php echo esc_attr($btn_class); ?>" type="submit"><?php echo esc_html($label); ?></button>
		</form>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_handle_favorite_action')) {
	/**
	 * Handle favorite toggle POST action.
	 */
	function psymod_account_handle_favorite_action(): void
	{
		if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
			return;
		}

		$action = isset($_POST['psymod_account_action']) ? sanitize_text_field(wp_unslash($_POST['psymod_account_action'])) : '';
		if ($action !== 'toggle_favorite') {
			return;
		}
		if (! is_user_logged_in()) {
			return;
		}

		$nonce = isset($_POST['psymod_account_favorite_nonce']) ? sanitize_text_field(wp_unslash($_POST['psymod_account_favorite_nonce'])) : '';
		if ($nonce === '' || ! wp_verify_nonce($nonce, 'psymod_account_favorite_action')) {
			return;
		}

		$post_id = isset($_POST['psymod_post_id']) ? absint(wp_unslash($_POST['psymod_post_id'])) : 0;
		if ($post_id > 0) {
			psymod_account_toggle_material_favorite($post_id);
		}

		$redirect_to = isset($_POST['psymod_redirect_to']) ? esc_url_raw(wp_unslash($_POST['psymod_redirect_to'])) : '';
		if ($redirect_to === '') {
			$redirect_to = wp_get_referer();
		}
		if (! is_string($redirect_to) || $redirect_to === '') {
			$redirect_to = home_url('/account/');
		}

		wp_safe_redirect($redirect_to);
		exit;
	}
}

if (! function_exists('psymod_account_get_user_recently_viewed')) {
	/**
	 * Get recently viewed materials from user meta.
	 *
	 * @return int[]
	 */
	function psymod_account_get_user_recently_viewed($user_id = 0): array
	{
		static $cache = array();

		$user_id = psymod_account_get_target_user_id($user_id);
		if ($user_id <= 0) {
			return array();
		}
		if (isset($cache[$user_id])) {
			return (array) $cache[$user_id];
		}

		$raw = get_user_meta($user_id, '_psymod_recently_viewed_materials', true);
		if (! is_array($raw)) {
			$raw = array();
		}

		$post_type = psymod_account_get_library_post_type();
		$ids = array();
		foreach ($raw as $item) {
			$post_id = absint($item);
			if ($post_id <= 0) {
				continue;
			}
			if (get_post_type($post_id) !== $post_type) {
				continue;
			}
			$ids[] = $post_id;
		}

		$cache[$user_id] = array_values(array_unique($ids));
		return (array) $cache[$user_id];
	}
}

if (! function_exists('psymod_account_track_recently_viewed_material')) {
	/**
	 * Track recently viewed material for logged-in users.
	 */
	function psymod_account_track_recently_viewed_material(): void
	{
		if (! is_user_logged_in()) {
			return;
		}
		if (! is_singular(psymod_account_get_library_post_type())) {
			return;
		}

		$post_id = absint(get_queried_object_id());
		if ($post_id <= 0 || ! psymod_account_user_can_access_material($post_id)) {
			return;
		}

		$user_id = psymod_account_get_target_user_id(0);
		if ($user_id <= 0) {
			return;
		}

		$recent = psymod_account_get_user_recently_viewed($user_id);
		$recent = array_values(array_filter($recent, static function (int $id) use ($post_id): bool {
			return $id !== $post_id;
		}));
		array_unshift($recent, $post_id);
		$recent = array_slice($recent, 0, 20);

		update_user_meta($user_id, '_psymod_recently_viewed_materials', $recent);
	}
}

if (! function_exists('psymod_account_render_available_materials')) {
	/**
	 * Render latest available materials for current user.
	 */
	function psymod_account_render_available_materials($limit = 6): string
	{
		$limit = psymod_account_normalize_shortcode_limit($limit, 6, 24);
		$post_type = psymod_account_get_library_post_type();
		if (! post_type_exists($post_type)) {
			return '';
		}

		$posts = get_posts(
			array(
				'post_type'      => $post_type,
				'post_status'    => 'publish',
				'posts_per_page' => max($limit * 4, 12),
				'orderby'        => 'date',
				'order'          => 'DESC',
				'no_found_rows'  => true,
			)
		);

		$available = array();
		foreach ($posts as $post) {
			if (! $post instanceof WP_Post) {
				continue;
			}
			if (! psymod_account_user_can_access_material((int) $post->ID)) {
				continue;
			}
			$available[] = $post;
			if (count($available) >= $limit) {
				break;
			}
		}

		ob_start();
		?>
		<section class="psymod-access-status">
			<div class="psymod-access-status-card">
				<h3 class="psymod-access-status-title"><?php echo esc_html__('Доступные материалы', 'psymod-library'); ?></h3>
				<?php if (empty($available)) : ?>
					<p class="psymod-account-notice"><?php echo esc_html__('Пока нет доступных материалов для вашего уровня.', 'psymod-library'); ?></p>
				<?php else : ?>
					<div class="psymod-account-materials-grid">
						<?php foreach ($available as $item) : ?>
							<article class="psymod-account-material-card">
								<?php echo psymod_account_get_material_badge_html((int) $item->ID); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
								<h4 class="psymod-account-material-title">
									<a href="<?php echo esc_url(get_permalink((int) $item->ID)); ?>"><?php echo esc_html(get_the_title((int) $item->ID)); ?></a>
								</h4>
								<p class="psymod-account-material-excerpt"><?php echo esc_html(psymod_account_get_material_excerpt_text((int) $item->ID)); ?></p>
							</article>
						<?php endforeach; ?>
					</div>
				<?php endif; ?>
			</div>
		</section>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_render_locked_materials_teaser')) {
	/**
	 * Render teaser cards for locked member/premium materials.
	 */
	function psymod_account_render_locked_materials_teaser($limit = 6): string
	{
		$limit = psymod_account_normalize_shortcode_limit($limit, 6, 24);
		$post_type = psymod_account_get_library_post_type();
		if (! post_type_exists($post_type)) {
			return '';
		}

		$posts = get_posts(
			array(
				'post_type'      => $post_type,
				'post_status'    => 'publish',
				'posts_per_page' => max($limit * 4, 12),
				'orderby'        => 'date',
				'order'          => 'DESC',
				'meta_query'     => array(
					array(
						'key'     => 'required_access_level',
						'value'   => array(PSYMOD_ACCESS_MEMBER, PSYMOD_ACCESS_PREMIUM),
						'compare' => 'IN',
					),
				),
				'no_found_rows'  => true,
			)
		);

		$locked = array();
		foreach ($posts as $post) {
			if (! $post instanceof WP_Post) {
				continue;
			}
			if (psymod_account_user_can_access_material((int) $post->ID)) {
				continue;
			}
			$locked[] = $post;
			if (count($locked) >= $limit) {
				break;
			}
		}

		$cta_url = is_user_logged_in() ? home_url('/account/') : home_url('/login/');
		$cta_label = is_user_logged_in() ? 'Обновить доступ' : 'Войти / Зарегистрироваться';

		if (empty($locked) && ! current_user_can('manage_options')) {
			return '';
		}

		ob_start();
		?>
		<section class="psymod-access-status">
			<div class="psymod-access-status-card">
				<h3 class="psymod-access-status-title"><?php echo esc_html__('Материалы с расширенным доступом', 'psymod-library'); ?></h3>
				<?php if (empty($locked)) : ?>
					<p class="psymod-account-notice"><?php echo esc_html__('Для вас сейчас нет заблокированных подборок в этом блоке.', 'psymod-library'); ?></p>
				<?php else : ?>
					<div class="psymod-account-materials-grid">
						<?php foreach ($locked as $item) : ?>
							<?php $level = psymod_account_get_material_access_level((int) $item->ID); ?>
							<article class="psymod-account-material-card">
								<?php echo psymod_account_get_material_badge_html((int) $item->ID); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
								<h4 class="psymod-account-material-title"><?php echo esc_html(get_the_title((int) $item->ID)); ?></h4>
								<p class="psymod-account-material-excerpt"><?php echo esc_html(psymod_account_get_material_excerpt_text((int) $item->ID)); ?></p>
								<div class="psymod-account-actions">
									<a class="psymod-account-cta" href="<?php echo esc_url($cta_url); ?>">
										<?php echo esc_html($level === PSYMOD_ACCESS_PREMIUM ? 'Открыть Premium' : $cta_label); ?>
									</a>
								</div>
							</article>
						<?php endforeach; ?>
					</div>
				<?php endif; ?>
			</div>
		</section>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_render_favorite_materials')) {
	/**
	 * Render favorite materials block.
	 */
	function psymod_account_render_favorite_materials($limit = 6): string
	{
		$limit = psymod_account_normalize_shortcode_limit($limit, 6, 24);
		if (! is_user_logged_in()) {
			return '';
		}

		$favorites = array_slice(psymod_account_get_user_favorites(0), 0, 100);
		if (! empty($favorites)) {
			$posts = get_posts(
				array(
					'post_type'      => psymod_account_get_library_post_type(),
					'post_status'    => 'publish',
					'post__in'       => $favorites,
					'orderby'        => 'post__in',
					'posts_per_page' => $limit,
					'no_found_rows'  => true,
				)
			);
		} else {
			$posts = array();
		}

		ob_start();
		?>
		<section class="psymod-account-section">
			<div class="psymod-access-status-card">
				<h3 class="psymod-account-section-title"><?php echo esc_html__('Избранные материалы', 'psymod-library'); ?></h3>
				<?php if (empty($posts)) : ?>
					<p class="psymod-account-empty"><?php echo esc_html__('У вас пока нет избранных материалов.', 'psymod-library'); ?></p>
				<?php else : ?>
					<div class="psymod-account-materials-grid">
						<?php foreach ($posts as $item) : ?>
							<?php if (! $item instanceof WP_Post) {
								continue;
							} ?>
							<article class="psymod-account-material-card">
								<?php echo psymod_account_get_material_badge_html((int) $item->ID); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
								<h4 class="psymod-account-material-title">
									<a href="<?php echo esc_url(get_permalink((int) $item->ID)); ?>"><?php echo esc_html(get_the_title((int) $item->ID)); ?></a>
								</h4>
								<p class="psymod-account-material-excerpt"><?php echo esc_html(psymod_account_get_material_excerpt_text((int) $item->ID)); ?></p>
							</article>
						<?php endforeach; ?>
					</div>
				<?php endif; ?>
			</div>
		</section>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_render_recently_viewed_materials')) {
	/**
	 * Render recently viewed materials block.
	 */
	function psymod_account_render_recently_viewed_materials($limit = 6): string
	{
		$limit = psymod_account_normalize_shortcode_limit($limit, 6, 24);
		if (! is_user_logged_in()) {
			return '';
		}

		$recent = array_slice(psymod_account_get_user_recently_viewed(0), 0, 20);
		if (! empty($recent)) {
			$posts = get_posts(
				array(
					'post_type'      => psymod_account_get_library_post_type(),
					'post_status'    => 'publish',
					'post__in'       => $recent,
					'orderby'        => 'post__in',
					'posts_per_page' => $limit,
					'no_found_rows'  => true,
				)
			);
		} else {
			$posts = array();
		}

		ob_start();
		?>
		<section class="psymod-account-section">
			<div class="psymod-access-status-card">
				<h3 class="psymod-account-section-title"><?php echo esc_html__('Недавно просмотренные', 'psymod-library'); ?></h3>
				<?php if (empty($posts)) : ?>
					<p class="psymod-account-empty"><?php echo esc_html__('Вы пока не просматривали материалы.', 'psymod-library'); ?></p>
				<?php else : ?>
					<div class="psymod-account-materials-grid">
						<?php foreach ($posts as $item) : ?>
							<?php if (! $item instanceof WP_Post) {
								continue;
							} ?>
							<article class="psymod-account-material-card">
								<?php echo psymod_account_get_material_badge_html((int) $item->ID); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
								<h4 class="psymod-account-material-title">
									<a href="<?php echo esc_url(get_permalink((int) $item->ID)); ?>"><?php echo esc_html(get_the_title((int) $item->ID)); ?></a>
								</h4>
								<p class="psymod-account-material-excerpt"><?php echo esc_html(psymod_account_get_material_excerpt_text((int) $item->ID)); ?></p>
							</article>
						<?php endforeach; ?>
					</div>
				<?php endif; ?>
			</div>
		</section>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_access_status_shortcode')) {
	/**
	 * Shortcode [psymod_access_status].
	 */
	function psymod_account_access_status_shortcode(): string
	{
		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo psymod_account_render_user_access_status(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_get_system_checklist')) {
	/**
	 * Get basic system health checklist for account/access MVP.
	 *
	 * @return array<string,bool>
	 */
	function psymod_account_get_system_checklist(): array
	{
		global $shortcode_tags;

		$required_functions = array(
			'psymod_account_current_user_access_level',
			'psymod_account_user_can_access_material',
			'psymod_account_get_material_access_level',
			'psymod_account_get_category_inherited_access_level',
			'psymod_account_get_user_favorites',
			'psymod_account_get_user_recently_viewed',
		);
		$functions_ok = true;
		foreach ($required_functions as $function_name) {
			if (! function_exists($function_name)) {
				$functions_ok = false;
				break;
			}
		}

		$shortcodes = array(
			'psymod_account',
			'psymod_access_status',
			'psymod_available_materials',
			'psymod_locked_materials',
			'psymod_favorite_materials',
			'psymod_recently_viewed_materials',
			'psymod_account_dashboard',
		);
		$shortcodes_ok = true;
		foreach ($shortcodes as $shortcode) {
			if (! isset($shortcode_tags[$shortcode])) {
				$shortcodes_ok = false;
				break;
			}
		}

		return array(
			'CPT exists'             => post_type_exists(psymod_account_get_library_post_type()),
			'required functions'     => $functions_ok,
			'shortcodes registered'  => $shortcodes_ok,
			'user meta keys active'  => true,
			'access constants defined' => defined('PSYMOD_ACCESS_PUBLIC') && defined('PSYMOD_ACCESS_REGISTERED') && defined('PSYMOD_ACCESS_MEMBER') && defined('PSYMOD_ACCESS_PREMIUM'),
		);
	}
}

if (! function_exists('psymod_account_access_debug_shortcode')) {
	/**
	 * Admin-only debug shortcode: [psymod_access_debug].
	 */
	function psymod_account_access_debug_shortcode(): string
	{
		if (! current_user_can('manage_options')) {
			return '';
		}

		$user          = wp_get_current_user();
		$user_id       = $user instanceof WP_User ? (int) $user->ID : 0;
		$roles         = $user instanceof WP_User ? implode(', ', (array) $user->roles) : '';
		$post_type     = psymod_account_get_library_post_type();
		$access_mode   = psymod_account_get_query_mode();
		$is_single     = is_singular($post_type);
		$single_post_id = $is_single ? absint(get_queried_object_id()) : 0;

		$override = '';
		$material_level = PSYMOD_ACCESS_PUBLIC;
		$can_access = false;
		$category_inherited = PSYMOD_ACCESS_PUBLIC;
		$section_level = PSYMOD_ACCESS_PUBLIC;

		if ($single_post_id > 0) {
			$override          = sanitize_text_field((string) get_post_meta($single_post_id, 'required_access_level', true));
			$material_level    = psymod_account_get_material_access_level($single_post_id);
			$can_access        = psymod_account_user_can_access_material($single_post_id);
			$category_inherited = psymod_account_get_category_inherited_access_level($single_post_id);
			$section_level     = psymod_account_get_section_access_level($single_post_id);
		}

		$checks = psymod_account_get_system_checklist();

		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		?>
		<div class="psymod-account">
			<div class="psymod-account-card">
				<h3 class="psymod-account-section-title"><?php echo esc_html__('PSYMOD Access Debug', 'psymod-library'); ?></h3>
				<p class="psymod-account-notice"><?php echo esc_html('user_id: ' . (string) $user_id); ?></p>
				<p class="psymod-account-notice"><?php echo esc_html('user_access_level: ' . psymod_account_current_user_access_level()); ?></p>
				<p class="psymod-account-notice"><?php echo esc_html('is_logged_in: ' . (is_user_logged_in() ? 'yes' : 'no')); ?></p>
				<p class="psymod-account-notice"><?php echo esc_html('roles: ' . $roles); ?></p>
				<p class="psymod-account-notice"><?php echo esc_html('library_post_type: ' . $post_type); ?></p>
				<p class="psymod-account-notice"><?php echo esc_html('access_mode: ' . $access_mode); ?></p>

				<?php if ($single_post_id > 0) : ?>
					<hr>
					<p class="psymod-account-notice"><?php echo esc_html('material_id: ' . (string) $single_post_id); ?></p>
					<p class="psymod-account-notice"><?php echo esc_html('material_access_level: ' . $material_level); ?></p>
					<p class="psymod-account-notice"><?php echo esc_html('user_can_access: ' . ($can_access ? 'yes' : 'no')); ?></p>
					<p class="psymod-account-notice"><?php echo esc_html('inherited_category_access: ' . $category_inherited); ?></p>
					<p class="psymod-account-notice"><?php echo esc_html('inherited_section_access: ' . $section_level); ?></p>
					<p class="psymod-account-notice"><?php echo esc_html('material_override_raw: ' . ($override !== '' ? $override : '(empty)')); ?></p>
				<?php endif; ?>

				<hr>
				<?php foreach ($checks as $check_name => $status) : ?>
					<p class="psymod-account-notice"><?php echo esc_html($check_name . ': ' . ($status ? 'OK' : 'FAIL')); ?></p>
				<?php endforeach; ?>
			</div>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_available_materials_shortcode')) {
	/**
	 * Shortcode [psymod_available_materials limit="6"].
	 */
	function psymod_account_available_materials_shortcode(array $atts = array()): string
	{
		$atts = shortcode_atts(
			array(
				'limit' => 6,
			),
			$atts,
			'psymod_available_materials'
		);

		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo psymod_account_render_available_materials(psymod_account_normalize_shortcode_limit($atts['limit'], 6, 24)); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_locked_materials_shortcode')) {
	/**
	 * Shortcode [psymod_locked_materials limit="6"].
	 */
	function psymod_account_locked_materials_shortcode(array $atts = array()): string
	{
		$atts = shortcode_atts(
			array(
				'limit' => 6,
			),
			$atts,
			'psymod_locked_materials'
		);

		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo psymod_account_render_locked_materials_teaser(psymod_account_normalize_shortcode_limit($atts['limit'], 6, 24)); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_favorite_materials_shortcode')) {
	/**
	 * Shortcode [psymod_favorite_materials limit="6"].
	 */
	function psymod_account_favorite_materials_shortcode(array $atts = array()): string
	{
		$atts = shortcode_atts(
			array(
				'limit' => 6,
			),
			$atts,
			'psymod_favorite_materials'
		);

		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo psymod_account_render_favorite_materials(psymod_account_normalize_shortcode_limit($atts['limit'], 6, 24)); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_recently_viewed_materials_shortcode')) {
	/**
	 * Shortcode [psymod_recently_viewed_materials limit="6"].
	 */
	function psymod_account_recently_viewed_materials_shortcode(array $atts = array()): string
	{
		$atts = shortcode_atts(
			array(
				'limit' => 6,
			),
			$atts,
			'psymod_recently_viewed_materials'
		);

		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo psymod_account_render_recently_viewed_materials(psymod_account_normalize_shortcode_limit($atts['limit'], 6, 24)); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_full_dashboard_shortcode')) {
	/**
	 * Shortcode [psymod_account_dashboard].
	 */
	function psymod_account_full_dashboard_shortcode(array $atts = array()): string
	{
		$atts = shortcode_atts(
			array(
				'limit' => 6,
			),
			$atts,
			'psymod_account_dashboard'
		);

		$limit = psymod_account_normalize_shortcode_limit($atts['limit'], 6, 24);

		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		?>
		<div class="psymod-account-dashboard">
			<?php echo psymod_account_render_user_access_status(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php echo psymod_account_render_my_subscription_panel(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php echo psymod_account_render_available_materials($limit); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php echo psymod_account_render_favorite_materials($limit); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php echo psymod_account_render_recently_viewed_materials($limit); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php echo psymod_account_render_locked_materials_teaser($limit); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_dashboard_shortcode')) {
	/**
	 * Shortcode [psymod_account].
	 */
	function psymod_account_dashboard_shortcode(): string
	{
		$login_url    = wp_login_url(home_url('/account/'));
		$register_url = home_url('/register/');
		$logout_url   = wp_logout_url(home_url('/login/'));
		$user         = wp_get_current_user();

		ob_start();
		echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		?>
		<div class="psymod-account">
			<?php echo psymod_account_get_notice(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php if (! is_user_logged_in()) : ?>
				<div class="psymod-account--auth">
					<div class="psymod-account-card">
					<h2 class="psymod-account-title"><?php echo esc_html__('Личный кабинет', 'psymod-library'); ?></h2>
					<p class="psymod-account-notice"><?php echo esc_html__('Войдите, чтобы получить доступ к личному кабинету.', 'psymod-library'); ?></p>
					<div class="psymod-account-actions">
						<a class="psymod-account-button psymod-account-button--primary" href="<?php echo esc_url($login_url); ?>"><?php echo esc_html__('Войти', 'psymod-library'); ?></a>
						<a class="psymod-account-button psymod-account-button--secondary" href="<?php echo esc_url($register_url); ?>"><?php echo esc_html__('Зарегистрироваться', 'psymod-library'); ?></a>
					</div>
					</div>
				</div>
			<?php else : ?>
				<?php $user_access = psymod_account_get_user_level($user instanceof WP_User ? (int) $user->ID : 0); ?>
				<div class="psymod-account-dashboard">
					<section class="psymod-account-hero">
						<div>
							<span class="psymod-account-eyebrow"><?php echo esc_html__('Личный кабинет', 'psymod-library'); ?></span>
							<h1><?php echo esc_html__('Добро пожаловать обратно', 'psymod-library'); ?></h1>
							<p><?php echo esc_html($user instanceof WP_User ? (string) $user->user_email : ''); ?></p>
						</div>
						<span class="psymod-account-level-badge"><?php echo esc_html(psymod_account_get_access_label($user_access)); ?></span>
					</section>

					<div class="psymod-account-grid">
						<div class="psymod-account-panel">
							<h3><?php echo esc_html__('Текущий доступ', 'psymod-library'); ?></h3>
							<p><?php echo esc_html(sprintf(__('Ваш уровень: %s', 'psymod-library'), psymod_account_get_access_label($user_access))); ?></p>
							<p><?php echo esc_html__('Доступные материалы подбираются автоматически.', 'psymod-library'); ?></p>
						</div>
						<div class="psymod-account-panel">
							<h3><?php echo esc_html__('Следующий шаг', 'psymod-library'); ?></h3>
							<p><?php echo esc_html__('Откройте библиотеку и продолжите с материалами, которые доступны вашему уровню.', 'psymod-library'); ?></p>
						</div>
					</div>

					<section class="psymod-account-recommend">
						<h3><?php echo esc_html__('Рекомендуем начать', 'psymod-library'); ?></h3>
						<p><?php echo esc_html__('Перейдите в библиотеку и выберите раздел CORE, PRO или бесплатные материалы.', 'psymod-library'); ?></p>
					</section>

					<?php echo psymod_account_render_my_subscription_panel(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>

					<div class="psymod-account-actions">
						<a class="psymod-account-button psymod-account-button--secondary" href="<?php echo esc_url($logout_url); ?>"><?php echo esc_html__('Выйти', 'psymod-library'); ?></a>
					</div>
				</div>
			<?php endif; ?>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_pricing_cards_shortcode')) {
	/**
	 * Render pricing cards block for subscriptions page.
	 */
	function psymod_account_pricing_cards_shortcode(): string
	{
		$cards = array(
			array(
				'title' => 'CORE Monthly',
				'url'   => '/product/core-monthly/',
				'image' => 'https://psymod.org/wp-content/uploads/2026/05/image1.png',
			),
			array(
				'title' => 'PRO Monthly',
				'url'   => '/product/pro-monthly/',
				'image' => 'https://psymod.org/wp-content/uploads/2026/05/image3-1.png',
			),
			array(
				'title' => 'PRO Yearly',
				'url'   => '/product/pro-yearly/',
				'image' => 'https://psymod.org/wp-content/uploads/2026/05/image4-1.png',
			),
		);

		ob_start();
		?>
		<?php echo psymod_account_render_styles(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		<section class="psymod-pricing-section" aria-label="<?php echo esc_attr__('PSYMOD subscriptions', 'psymod-library'); ?>">
			<div class="psymod-pricing-shell">
				<header class="psymod-pricing-header">
					<h2 class="psymod-pricing-title"><?php echo esc_html__('Выберите подписку', 'psymod-library'); ?></h2>
					<p class="psymod-pricing-subtitle"><?php echo esc_html__('Откройте доступ к материалам PSYMOD в удобном формате.', 'psymod-library'); ?></p>
				</header>

				<div class="psymod-pricing-grid">
					<?php foreach ($cards as $card) : ?>
						<?php $card_url = home_url((string) $card['url']); ?>
						<div class="psymod-pricing-card">
							<a class="psymod-pricing-card-link" href="<?php echo esc_url($card_url); ?>" aria-label="<?php echo esc_attr((string) $card['title']); ?>"></a>
							<div class="psymod-pricing-card-media">
								<img class="psymod-pricing-card-image" src="<?php echo esc_url((string) $card['image']); ?>" alt="<?php echo esc_attr((string) $card['title']); ?>">
							</div>
							<a class="psymod-pricing-card-action" href="<?php echo esc_url($card_url); ?>">
								<?php echo esc_html(sprintf('Выбрать %s', (string) $card['title'])); ?>
							</a>
						</div>
					<?php endforeach; ?>
				</div>
			</div>
		</section>
		<?php

		return (string) ob_get_clean();
	}
}

if (! function_exists('psymod_account_register_shortcodes')) {
	/**
	 * Register account shortcodes.
	 */
	function psymod_account_register_shortcodes(): void
	{
		add_shortcode('psymod_login', 'psymod_account_login_shortcode');
		add_shortcode('psymod_register', 'psymod_account_register_shortcode');
		add_shortcode('psymod_reset_password', 'psymod_account_reset_password_shortcode');
		add_shortcode('psymod_account', 'psymod_account_dashboard_shortcode');
		add_shortcode('psymod_access_status', 'psymod_account_access_status_shortcode');
		add_shortcode('psymod_available_materials', 'psymod_account_available_materials_shortcode');
		add_shortcode('psymod_locked_materials', 'psymod_account_locked_materials_shortcode');
		add_shortcode('psymod_favorite_materials', 'psymod_account_favorite_materials_shortcode');
		add_shortcode('psymod_recently_viewed_materials', 'psymod_account_recently_viewed_materials_shortcode');
		add_shortcode('psymod_account_dashboard', 'psymod_account_full_dashboard_shortcode');
		add_shortcode('psymod_access_debug', 'psymod_account_access_debug_shortcode');
		add_shortcode('psymod_pricing_cards', 'psymod_account_pricing_cards_shortcode');
		add_shortcode('psymod_my_subscription', 'psymod_account_my_subscription_shortcode');
	}
}

if (! function_exists('psymod_account_register_access_debug_shortcode')) {
	/**
	 * Safety registration for [psymod_access_debug].
	 */
	function psymod_account_register_access_debug_shortcode(): void
	{
		add_shortcode('psymod_access_debug', 'psymod_account_access_debug_shortcode');
	}
}

add_action('init', 'psymod_account_register_shortcodes');
add_action('init', 'psymod_account_register_access_debug_shortcode', 20);
add_action('init', 'psymod_account_handle_login');
add_action('init', 'psymod_account_handle_register');
add_action('init', 'psymod_account_handle_reset_password');
add_action('init', 'psymod_account_handle_favorite_action');
add_action('admin_init', 'psymod_account_register_term_access_admin_hooks');
add_action('admin_init', 'psymod_account_register_term_access_columns_hooks');
add_action('add_meta_boxes', 'psymod_account_register_material_access_metabox');
add_action('save_post', 'psymod_account_save_material_access_level');
add_action('pre_get_posts', 'psymod_account_filter_library_query_by_access');
add_action('template_redirect', 'psymod_account_track_recently_viewed_material');
add_filter('the_content', 'psymod_account_filter_single_material_content', 999);
add_filter('do_shortcode_tag', 'psymod_account_inject_access_badges_into_library_cards', 10, 2);
