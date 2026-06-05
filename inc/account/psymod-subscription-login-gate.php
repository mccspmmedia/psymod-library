<?php
/**
 * PSYMOD subscription login gate.
 *
 * Redirect guests from subscription products to login page and return back
 * to the selected tariff after successful authentication.
 *
 * @package PSYMOD_Library
 */

if (! defined('ABSPATH')) {
	exit;
}

if (! function_exists('psymod_subscription_login_gate_log')) {
	/**
	 * Log login gate events.
	 */
	function psymod_subscription_login_gate_log(string $message, array $context = array()): void
	{
		$context['source'] = 'psymod-subscription-login-gate';

		if (function_exists('wc_get_logger')) {
			$logger = wc_get_logger();
			$logger->info($message, $context);
			return;
		}

		error_log('[psymod-subscription-login-gate] ' . $message . ' ' . wp_json_encode($context));
	}
}

if (! function_exists('psymod_subscription_login_gate_get_product_slugs')) {
	/**
	 * Return subscription product slugs protected by login gate.
	 *
	 * @return string[]
	 */
	function psymod_subscription_login_gate_get_product_slugs(): array
	{
		$slugs = array(
			'core-monthly',
			'pro-monthly',
			'pro-yearly',
		);

		$slugs = apply_filters('psymod_subscription_login_gate_product_slugs', $slugs);
		$slugs = array_values(array_unique(array_filter(array_map('sanitize_title', (array) $slugs))));

		return $slugs;
	}
}

if (! function_exists('psymod_subscription_login_gate_get_product_ids')) {
	/**
	 * Return optional subscription product IDs protected by login gate.
	 *
	 * @return int[]
	 */
	function psymod_subscription_login_gate_get_product_ids(): array
	{
		$ids = apply_filters('psymod_subscription_login_gate_product_ids', array());
		$ids = array_values(array_unique(array_filter(array_map('absint', (array) $ids))));

		return $ids;
	}
}

if (! function_exists('psymod_subscription_login_gate_is_target_product_post')) {
	/**
	 * Check if a product post should be gated for guests.
	 */
	function psymod_subscription_login_gate_is_target_product_post(WP_Post $post): bool
	{
		if ($post->post_type !== 'product') {
			return false;
		}

		$product_id = absint($post->ID);
		$product_ids = psymod_subscription_login_gate_get_product_ids();
		if ($product_id > 0 && in_array($product_id, $product_ids, true)) {
			return true;
		}

		$slug = sanitize_title((string) $post->post_name);
		return $slug !== '' && in_array($slug, psymod_subscription_login_gate_get_product_slugs(), true);
	}
}

if (! function_exists('psymod_subscription_login_gate_is_target_product_url')) {
	/**
	 * Validate redirect target and ensure it points to one of subscription products.
	 */
	function psymod_subscription_login_gate_is_target_product_url(string $url): bool
	{
		$url = trim($url);
		if ($url === '') {
			return false;
		}

		$path = (string) wp_parse_url($url, PHP_URL_PATH);
		$path = trim($path, '/');
		if ($path === '') {
			return false;
		}

		if (preg_match('#(?:^|/)product/([^/]+)/?$#i', $path, $matches) !== 1 || empty($matches[1])) {
			return false;
		}

		$slug = sanitize_title((string) $matches[1]);
		return $slug !== '' && in_array($slug, psymod_subscription_login_gate_get_product_slugs(), true);
	}
}

if (! function_exists('psymod_subscription_login_gate_is_target_library_url')) {
	/**
	 * Validate redirect target for protected library sections.
	 */
	function psymod_subscription_login_gate_is_target_library_url(string $url): bool
	{
		$url = trim($url);
		if ($url === '') {
			return false;
		}

		$path = (string) wp_parse_url($url, PHP_URL_PATH);
		$path = trim($path, '/');
		if ($path === '') {
			return false;
		}

		return preg_match('#(?:^|/)library(?:/(?:core|pro|scenario|free|modules))?/?$#i', $path) === 1;
	}
}

if (! function_exists('psymod_subscription_login_gate_get_redirect_target_type')) {
	/**
	 * Get allowed redirect target type.
	 *
	 * @return string product|library|''
	 */
	function psymod_subscription_login_gate_get_redirect_target_type(string $url): string
	{
		if (psymod_subscription_login_gate_is_target_product_url($url)) {
			return 'product';
		}

		if (psymod_subscription_login_gate_is_target_library_url($url)) {
			return 'library';
		}

		return '';
	}
}

if (! function_exists('psymod_subscription_login_gate_is_allowed_redirect_url')) {
	/**
	 * Check whether redirect URL is allowed by PSYMOD login gate policy.
	 */
	function psymod_subscription_login_gate_is_allowed_redirect_url(string $url): bool
	{
		return psymod_subscription_login_gate_get_redirect_target_type($url) !== '';
	}
}

if (! function_exists('psymod_subscription_login_gate_get_safe_redirect_target_from_request')) {
	/**
	 * Get safe redirect target from request.
	 */
	function psymod_subscription_login_gate_get_safe_redirect_target_from_request(): string
	{
		if (! isset($_REQUEST['redirect_to'])) {
			return '';
		}

		$raw = (string) wp_unslash($_REQUEST['redirect_to']);
		if ($raw === '') {
			return '';
		}

		$decoded = rawurldecode($raw);
		if ($decoded === '') {
			return '';
		}

		$candidate = $decoded;
		$host = (string) wp_parse_url($candidate, PHP_URL_HOST);

		// Accept local paths and convert them to absolute URLs.
		if ($host === '' && strpos($candidate, '/') === 0) {
			$candidate = home_url($candidate);
		}

		$validated = wp_validate_redirect($candidate, '');
		if (! is_string($validated) || $validated === '') {
			return '';
		}

		if (! psymod_subscription_login_gate_is_allowed_redirect_url($validated)) {
			return '';
		}

		return $validated;
	}
}

if (! function_exists('psymod_subscription_login_gate_redirect_guest_from_subscription_product')) {
	/**
	 * Redirect guests from subscription products to WooCommerce account login.
	 */
	function psymod_subscription_login_gate_redirect_guest_from_subscription_product(): void
	{
		if (is_admin() || is_user_logged_in()) {
			return;
		}

		if (! function_exists('is_product') || ! is_product()) {
			return;
		}

		global $post;
		if (! ($post instanceof WP_Post) || ! psymod_subscription_login_gate_is_target_product_post($post)) {
			return;
		}

		$product_url = get_permalink($post->ID);
		if (! is_string($product_url) || $product_url === '') {
			return;
		}

		$account_url = function_exists('wc_get_page_permalink') ? wc_get_page_permalink('myaccount') : '';
		if (! is_string($account_url) || $account_url === '') {
			$account_url = home_url('/my-account/');
		}

		$login_url = add_query_arg('redirect_to', rawurlencode($product_url), $account_url);
		psymod_subscription_login_gate_log(
			'Guest redirected to login before subscription purchase',
			array(
				'product_id'  => absint($post->ID),
				'product_url' => $product_url,
				'login_url'   => $login_url,
			)
		);

		wp_safe_redirect($login_url);
		exit;
	}
}

if (! function_exists('psymod_subscription_login_gate_redirect_guest_from_library_routes')) {
	/**
	 * Redirect guests from protected library routes to WooCommerce account login.
	 */
	function psymod_subscription_login_gate_redirect_guest_from_library_routes(): void
	{
		if (is_admin() || is_user_logged_in()) {
			return;
		}

		$request_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
		if ($request_uri === '') {
			return;
		}

		$path = trim((string) wp_parse_url($request_uri, PHP_URL_PATH), '/');
		if ($path === '' || preg_match('#(?:^|/)library(?:/(?:core|pro|scenario|free|modules))?/?$#i', $path) !== 1) {
			return;
		}

		$requested_url = home_url('/' . ltrim($request_uri, '/'));
		if (! is_string($requested_url) || $requested_url === '' || ! psymod_subscription_login_gate_is_target_library_url($requested_url)) {
			return;
		}

		$account_url = function_exists('wc_get_page_permalink') ? wc_get_page_permalink('myaccount') : '';
		if (! is_string($account_url) || $account_url === '') {
			$account_url = home_url('/my-account/');
		}

		$login_url = add_query_arg('redirect_to', rawurlencode($requested_url), $account_url);
		psymod_subscription_login_gate_log(
			'Guest redirected to login before opening protected library route',
			array(
				'requested_url' => $requested_url,
				'login_url'     => $login_url,
			)
		);

		wp_safe_redirect($login_url);
		exit;
	}
}

if (! function_exists('psymod_subscription_login_gate_woocommerce_login_redirect')) {
	/**
	 * Return user to selected subscription product after login.
	 *
	 * @param string          $redirect Default redirect URL.
	 * @param WP_User|WP_Error $user    Authenticated user object.
	 */
	function psymod_subscription_login_gate_woocommerce_login_redirect(string $redirect, $user): string
	{
		if (! ($user instanceof WP_User)) {
			return $redirect;
		}

		$target = psymod_subscription_login_gate_get_safe_redirect_target_from_request();
		if ($target === '') {
			return $redirect;
		}

		psymod_subscription_login_gate_log(
			'Post-login redirect to subscription product',
			array(
				'user_id' => absint($user->ID),
				'target'  => $target,
			)
		);

		return $target;
	}
}

if (! function_exists('psymod_subscription_login_gate_render_login_notice')) {
	/**
	 * Render helper notice on WooCommerce My Account login form when redirect_to points
	 * to protected subscription products.
	 */
	function psymod_subscription_login_gate_render_login_notice(): void
	{
		if (is_user_logged_in()) {
			return;
		}

		if (! function_exists('is_account_page') || ! is_account_page()) {
			return;
		}

		$target = psymod_subscription_login_gate_get_safe_redirect_target_from_request();
		if ($target === '') {
			return;
		}

		$target_type = psymod_subscription_login_gate_get_redirect_target_type($target);
		$message = 'Чтобы открыть доступ к материалам PSYMOD, необходимо войти в аккаунт или зарегистрироваться. После входа вы вернётесь к выбранному разделу.';
		if ($target_type === 'product') {
			$message = 'Чтобы оформить подписку и открыть доступ к материалам PSYMOD, необходимо войти в аккаунт или зарегистрироваться. После входа вы вернётесь к выбранному тарифу и сможете продолжить оплату.';
		}

		$create_account_url = add_query_arg(
			array(
				'redirect_to' => rawurlencode($target),
			),
			home_url('/register/')
		);
		?>
		<div class="psymod-subscription-login-gate-notice" style="margin:0 0 18px;padding:16px 18px;border:1px solid #dbeafe;background:#eff6ff;border-radius:14px;color:#1e3a8a;line-height:1.55;">
			<p style="margin:0 0 10px;font-weight:600;"><?php echo esc_html($message); ?></p>
			<a href="<?php echo esc_url($create_account_url); ?>" style="display:inline-flex;align-items:center;justify-content:center;min-height:38px;padding:0 14px;border-radius:10px;background:#111827;color:#fff;text-decoration:none;font-weight:600;">
				<?php echo esc_html__('Создать аккаунт', 'psymod-library'); ?>
			</a>
		</div>
		<?php
	}
}

if (! function_exists('psymod_subscription_login_gate_disable_woocommerce_registration_on_my_account')) {
	/**
	 * Force My Account page to display login form only (no Woo registration block).
	 */
	function psymod_subscription_login_gate_disable_woocommerce_registration_on_my_account($value): string
	{
		$current_value = is_string($value) ? $value : 'no';

		if (is_admin()) {
			return $current_value;
		}

		if (function_exists('is_account_page') && is_account_page()) {
			return 'no';
		}

		$request_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
		$path        = trim((string) wp_parse_url($request_uri, PHP_URL_PATH), '/');
		if ($path !== '' && preg_match('#(?:^|/)my-account/?$#i', $path) === 1) {
			return 'no';
		}

		return $current_value;
	}
}

add_action('template_redirect', 'psymod_subscription_login_gate_redirect_guest_from_subscription_product', 5);
add_action('template_redirect', 'psymod_subscription_login_gate_redirect_guest_from_library_routes', 6);
add_filter('woocommerce_login_redirect', 'psymod_subscription_login_gate_woocommerce_login_redirect', 10, 2);
add_action('woocommerce_before_customer_login_form', 'psymod_subscription_login_gate_render_login_notice', 5);
add_filter('option_woocommerce_enable_myaccount_registration', 'psymod_subscription_login_gate_disable_woocommerce_registration_on_my_account', 20);
