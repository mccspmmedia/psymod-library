<?php
/**
 * PSYMOD subscription access sync with WooCommerce Subscriptions.
 *
 * @package PSYMOD_Library
 */

if (! defined('ABSPATH')) {
	exit;
}

if (! function_exists('psymod_subscription_access_log')) {
	/**
	 * Log subscription access events.
	 */
	function psymod_subscription_access_log(string $message, array $context = array()): void
	{
		$context['source'] = 'psymod-subscription-access';

		if (function_exists('wc_get_logger')) {
			$logger = wc_get_logger();
			$logger->info($message, $context);
			return;
		}

		error_log('[psymod-subscription-access] ' . $message . ' ' . wp_json_encode($context));
	}
}

if (! function_exists('psymod_subscription_access_register_roles')) {
	/**
	 * Register subscription roles used by access sync.
	 */
	function psymod_subscription_access_register_roles(): void
	{
		$capabilities = array(
			'read'         => true,
			'upload_files' => false,
			'edit_posts'   => false,
			'delete_posts' => false,
		);

		add_role('psymod_core', 'PSYMOD CORE', $capabilities);
		add_role('psymod_pro', 'PSYMOD PRO', $capabilities);
	}
}

if (! function_exists('psymod_subscription_access_is_protected_role_user')) {
	/**
	 * Skip role overrides for privileged users.
	 */
	function psymod_subscription_access_is_protected_role_user(WP_User $user): bool
	{
		$roles = (array) $user->roles;
		return in_array('administrator', $roles, true) || in_array('editor', $roles, true);
	}
}

if (! function_exists('psymod_subscription_access_get_product_map')) {
	/**
	 * Product-to-access map.
	 *
	 * IDs can be overridden later via filter.
	 */
	function psymod_subscription_access_get_product_map(): array
	{
		$map = array(
			'core' => array(
				'ids'   => array(),
				// Keep "core yearly" for legacy subscriptions already sold in the past.
				'names' => array('core monthly', 'core yearly'),
			),
			'pro'  => array(
				'ids'   => array(),
				'names' => array('pro monthly', 'pro yearly'),
			),
		);

		$map = apply_filters('psymod_subscription_access_product_map', $map);

		$map['core']['ids']  = array_values(array_filter(array_map('absint', (array) ($map['core']['ids'] ?? array()))));
		$map['pro']['ids']   = array_values(array_filter(array_map('absint', (array) ($map['pro']['ids'] ?? array()))));
		$map['core']['names'] = array_values(array_filter(array_map('sanitize_text_field', (array) ($map['core']['names'] ?? array()))));
		$map['pro']['names']  = array_values(array_filter(array_map('sanitize_text_field', (array) ($map['pro']['names'] ?? array()))));

		return $map;
	}
}

if (! function_exists('psymod_subscription_access_detect_level_by_product')) {
	/**
	 * Detect access level by product IDs/names.
	 */
	function psymod_subscription_access_detect_level_by_product(int $product_id, string $product_name): string
	{
		$map         = psymod_subscription_access_get_product_map();
		$product_key = strtolower(trim($product_name));

		if ($product_id > 0 && in_array($product_id, $map['pro']['ids'], true)) {
			return 'pro';
		}
		if ($product_id > 0 && in_array($product_id, $map['core']['ids'], true)) {
			return 'core';
		}

		if ($product_key !== '' && in_array($product_key, array_map('strtolower', $map['pro']['names']), true)) {
			return 'pro';
		}
		if ($product_key !== '' && in_array($product_key, array_map('strtolower', $map['core']['names']), true)) {
			return 'core';
		}

		return '';
	}
}

if (! function_exists('psymod_subscription_access_resolve_subscription')) {
	/**
	 * Normalize subscription argument.
	 *
	 * @param mixed $subscription Subscription object or ID.
	 * @return WC_Subscription|null
	 */
	function psymod_subscription_access_resolve_subscription($subscription)
	{
		if (is_object($subscription) && method_exists($subscription, 'get_id') && method_exists($subscription, 'get_user_id')) {
			return $subscription;
		}

		$subscription_id = absint($subscription);
		if ($subscription_id <= 0 || ! function_exists('wcs_get_subscription')) {
			return null;
		}

		$resolved = wcs_get_subscription($subscription_id);
		if (! is_object($resolved) || ! method_exists($resolved, 'get_id') || ! method_exists($resolved, 'get_user_id')) {
			return null;
		}

		return $resolved;
	}
}

if (! function_exists('psymod_subscription_access_get_user_target_level')) {
	/**
	 * Get target role level based on user's active subscriptions.
	 */
	function psymod_subscription_access_get_user_target_level(int $user_id): string
	{
		$user_id = absint($user_id);
		if ($user_id <= 0 || ! function_exists('wcs_get_users_subscriptions')) {
			return '';
		}

		$subscriptions = wcs_get_users_subscriptions($user_id);
		if (empty($subscriptions) || ! is_array($subscriptions)) {
			return '';
		}

		$has_core = false;
		$has_pro  = false;

		foreach ($subscriptions as $subscription) {
			if (! is_object($subscription) || ! method_exists($subscription, 'has_status') || ! $subscription->has_status('active')) {
				continue;
			}

			$items = method_exists($subscription, 'get_items') ? $subscription->get_items() : array();
			if (empty($items)) {
				continue;
			}

			foreach ($items as $item) {
				if (! is_object($item) || ! method_exists($item, 'get_product_id')) {
					continue;
				}

				$product_id   = absint($item->get_product_id());
				$variation_id = method_exists($item, 'get_variation_id') ? absint($item->get_variation_id()) : 0;
				$product_name = method_exists($item, 'get_name') ? sanitize_text_field((string) $item->get_name()) : '';

				$level = psymod_subscription_access_detect_level_by_product($product_id, $product_name);
				if ($level === '' && $variation_id > 0) {
					$level = psymod_subscription_access_detect_level_by_product($variation_id, $product_name);
				}

				if ($level === 'pro') {
					$has_pro = true;
					break 2;
				}
				if ($level === 'core') {
					$has_core = true;
				}
			}
		}

		if ($has_pro) {
			return 'pro';
		}
		if ($has_core) {
			return 'core';
		}

		return '';
	}
}

if (! function_exists('psymod_subscription_access_apply_user_roles')) {
	/**
	 * Apply target access roles for a user.
	 */
	function psymod_subscription_access_apply_user_roles(int $user_id, string $target_level): void
	{
		$user_id = absint($user_id);
		if ($user_id <= 0) {
			return;
		}

		$user = get_userdata($user_id);
		if (! ($user instanceof WP_User)) {
			return;
		}

		if (psymod_subscription_access_is_protected_role_user($user)) {
			psymod_subscription_access_log('Skip protected role user', array('user_id' => $user_id, 'roles' => $user->roles));
			return;
		}

		$target_level = sanitize_text_field($target_level);

		// Remove both new and legacy access roles first.
		$user->remove_role('psymod_core');
		$user->remove_role('psymod_pro');
		$user->remove_role('core');
		$user->remove_role('pro');

		if ($target_level === 'pro') {
			$user->add_role('psymod_pro');
			$user->add_role('pro');
			psymod_subscription_access_log('Assigned PRO access', array('user_id' => $user_id));
			return;
		}

		if ($target_level === 'core') {
			$user->add_role('psymod_core');
			$user->add_role('core');
			psymod_subscription_access_log('Assigned CORE access', array('user_id' => $user_id));
			return;
		}

		// No active CORE/PRO subscriptions: keep a base customer role.
		$roles_after = (array) $user->roles;
		if (empty($roles_after)) {
			if (get_role('subscriber')) {
				$user->add_role('subscriber');
			} elseif (get_role('customer')) {
				$user->add_role('customer');
			}
		}

		psymod_subscription_access_log('Removed subscription access roles', array('user_id' => $user_id));
	}
}

if (! function_exists('psymod_subscription_access_sync_user_roles')) {
	/**
	 * Sync user roles from current active subscriptions.
	 */
	function psymod_subscription_access_sync_user_roles(int $user_id): void
	{
		$user_id = absint($user_id);
		if ($user_id <= 0) {
			return;
		}

		if (! function_exists('wcs_get_users_subscriptions')) {
			psymod_subscription_access_log('Subscriptions API is unavailable', array('user_id' => $user_id));
			return;
		}

		$target_level = psymod_subscription_access_get_user_target_level($user_id);
		psymod_subscription_access_apply_user_roles($user_id, $target_level);
		psymod_subscription_access_log('Subscription access synchronized', array('user_id' => $user_id, 'target_level' => $target_level));
	}
}

if (! function_exists('psymod_subscription_access_handle_status_event')) {
	/**
	 * Handle direct status hooks (active/cancelled/expired/etc).
	 *
	 * @param mixed $subscription Subscription object or ID.
	 */
	function psymod_subscription_access_handle_status_event($subscription): void
	{
		$resolved = psymod_subscription_access_resolve_subscription($subscription);
		if (! $resolved) {
			return;
		}

		$user_id = absint($resolved->get_user_id());
		psymod_subscription_access_log(
			'Subscription status event received',
			array(
				'subscription_id' => absint($resolved->get_id()),
				'user_id'         => $user_id,
				'status'          => method_exists($resolved, 'get_status') ? (string) $resolved->get_status() : '',
			)
		);

		psymod_subscription_access_sync_user_roles($user_id);
	}
}

if (! function_exists('psymod_subscription_access_handle_status_updated')) {
	/**
	 * Handle generic status transition hook.
	 *
	 * @param mixed  $subscription Subscription object or ID.
	 * @param string $new_status   New status.
	 * @param string $old_status   Old status.
	 */
	function psymod_subscription_access_handle_status_updated($subscription, string $new_status, string $old_status): void
	{
		$resolved = psymod_subscription_access_resolve_subscription($subscription);
		if (! $resolved) {
			return;
		}

		$user_id = absint($resolved->get_user_id());
		psymod_subscription_access_log(
			'Subscription status updated',
			array(
				'subscription_id' => absint($resolved->get_id()),
				'user_id'         => $user_id,
				'old_status'      => sanitize_text_field($old_status),
				'new_status'      => sanitize_text_field($new_status),
			)
		);

		psymod_subscription_access_sync_user_roles($user_id);
	}
}

add_action('init', 'psymod_subscription_access_register_roles', 20);

add_action('woocommerce_subscription_status_active', 'psymod_subscription_access_handle_status_event', 10, 1);
add_action('woocommerce_subscription_status_cancelled', 'psymod_subscription_access_handle_status_event', 10, 1);
add_action('woocommerce_subscription_status_expired', 'psymod_subscription_access_handle_status_event', 10, 1);
add_action('woocommerce_subscription_status_on-hold', 'psymod_subscription_access_handle_status_event', 10, 1);
add_action('woocommerce_subscription_status_pending-cancel', 'psymod_subscription_access_handle_status_event', 10, 1);
add_action('woocommerce_subscription_status_updated', 'psymod_subscription_access_handle_status_updated', 10, 3);
