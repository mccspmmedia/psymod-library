<?php
/**
 * Plugin Name: PSYMOD Library
 * Description: Starter plugin for PSYMOD library materials.
 * Version: 1.0.0
 * Author: PSYMOD
 */

if (! defined('ABSPATH')) {
	exit;
}

const PSYMOD_LIBRARY_POST_TYPE = 'psymod_material';
const PSYMOD_LIBRARY_NONCE_KEY = 'psymod_library_meta_nonce';

require_once plugin_dir_path(__FILE__) . 'inc/account/psymod-account.php';
require_once plugin_dir_path(__FILE__) . 'inc/account/psymod-subscription-access.php';
require_once plugin_dir_path(__FILE__) . 'inc/account/psymod-subscription-login-gate.php';

add_action('init', 'psymod_library_register_post_type');
add_action('init', 'psymod_library_register_taxonomies');
add_action('init', 'psymod_library_register_meta_fields');
add_action('init', 'psymod_library_register_rewrite_routes');
add_action('add_meta_boxes', 'psymod_library_register_meta_box');
add_action('save_post_' . PSYMOD_LIBRARY_POST_TYPE, 'psymod_library_save_meta_fields');
add_action('wp_enqueue_scripts', 'psymod_library_enqueue_styles');
add_shortcode('psymod_library', 'psymod_library_shortcode');
add_filter('the_content', 'psymod_library_hide_legacy_modules_page_content', 5);
add_filter('the_content', 'psymod_library_filter_protected_content');
add_filter('query_vars', 'psymod_library_register_query_vars');
add_filter('posts_join', 'psymod_library_search_posts_join', 10, 2);
add_filter('posts_where', 'psymod_library_search_posts_where', 10, 2);
add_filter('posts_distinct', 'psymod_library_search_posts_distinct', 10, 2);
add_filter('wp_nav_menu_objects', 'psymod_library_swap_login_menu_item', 10, 2);
add_action('template_redirect', 'psymod_library_force_modules_route_render', 1);
add_action('template_redirect', 'psymod_library_maybe_render_archive_page');
register_activation_hook(__FILE__, 'psymod_library_activate');

/**
 * Allowed access levels.
 */
function psymod_library_get_allowed_access_levels(): array
{
	return array('public', 'free_user', 'core', 'pro', 'admin_only');
}

/**
 * Access level labels.
 */
function psymod_library_get_access_level_labels(): array
{
	return array(
		'public'     => 'Public',
		'free_user'  => 'Free user',
		'core'       => 'CORE',
		'pro'        => 'PRO',
		'admin_only' => 'Admin only',
	);
}

/**
 * Sanitize access level with fallback.
 */
function psymod_library_sanitize_access_level($value): string
{
	$value   = sanitize_text_field((string) $value);
	$allowed = psymod_library_get_allowed_access_levels();

	if (! in_array($value, $allowed, true)) {
		return 'public';
	}

	return $value;
}

/**
 * Hide legacy WP page content on /library/modules route.
 *
 * This is a fallback guard: old modules page content can live in DB and should not
 * be mixed with the custom PSYMOD Library layout rendered via template_redirect.
 */
function psymod_library_hide_legacy_modules_page_content(string $content): string
{
	if (is_admin()) {
		return $content;
	}

	$request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
	$path        = trim((string) wp_parse_url($request_uri, PHP_URL_PATH), '/');
	$is_modules_route = preg_match('#(?:^|/)library/modules/?$#i', $path) === 1;

	if (! $is_modules_route) {
		return $content;
	}

	if (! is_singular('page')) {
		return $content;
	}

	if (! in_the_loop() || ! is_main_query()) {
		return $content;
	}

	return '';
}

/**
 * Force unified render for /library/modules route before other template handlers.
 *
 * This guards against legacy custom routes/content injected outside standard page flow.
 */
function psymod_library_force_modules_route_render(): void
{
	if (is_admin()) {
		return;
	}

	$request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
	$path        = trim((string) wp_parse_url($request_uri, PHP_URL_PATH), '/');
	$is_modules_route = preg_match('#(?:^|/)library/modules/?$#i', $path) === 1;

	if (! $is_modules_route) {
		return;
	}

	status_header(200);
	get_header();
	echo "\n<!-- PSYMOD MODULES FORCED RENDER -->\n";
	echo psymod_library_render_archive_page('modules'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	get_footer();
	exit;
}

/**
 * Swap header login menu item to account when user is logged in.
 *
 * @param WP_Post[] $items Menu items.
 * @param stdClass  $args  Menu args.
 * @return WP_Post[]
 */
function psymod_library_swap_login_menu_item(array $items, $args): array
{
	unset($args);

	$login_url_raw   = home_url('/login/');
	$account_url_raw = home_url('/account/');
	$login_url_cmp   = untrailingslashit($login_url_raw);
	$is_logged_in    = is_user_logged_in();

	foreach ($items as $item) {
		if (! isset($item->url)) {
			continue;
		}

		$item_url = untrailingslashit((string) $item->url);
		if ($item_url !== $login_url_cmp) {
			continue;
		}

		if ($is_logged_in) {
			$item->url   = $account_url_raw;
			$item->title = 'Личный кабинет';
		} else {
			$item->url   = $login_url_raw;
			$item->title = 'Войти';
		}
	}

	return $items;
}

/**
 * Sanitize related materials list to array of unique positive IDs.
 *
 * @param mixed $value Comma-separated string or array of IDs.
 * @return int[]
 */
function psymod_library_sanitize_related_materials($value): array
{
	$items = is_array($value) ? $value : explode(',', (string) $value);
	$ids   = array();

	foreach ($items as $item) {
		$id = absint(trim((string) $item));
		if ($id > 0) {
			$ids[] = $id;
		}
	}

	$ids = array_values(array_unique($ids));
	return $ids;
}

/**
 * Register custom post type.
 */
function psymod_library_register_post_type(): void
{
	register_post_type(
		PSYMOD_LIBRARY_POST_TYPE,
		array(
			'labels' => array(
				'name'               => __('Library Materials', 'psymod-library'),
				'singular_name'      => __('Library Material', 'psymod-library'),
				'add_new'            => __('Add New', 'psymod-library'),
				'add_new_item'       => __('Add New Material', 'psymod-library'),
				'edit_item'          => __('Edit Material', 'psymod-library'),
				'new_item'           => __('New Material', 'psymod-library'),
				'view_item'          => __('View Material', 'psymod-library'),
				'search_items'       => __('Search Materials', 'psymod-library'),
				'not_found'          => __('No materials found', 'psymod-library'),
				'not_found_in_trash' => __('No materials found in Trash', 'psymod-library'),
				'menu_name'          => __('PSYMOD Library', 'psymod-library'),
			),
			'public'             => true,
			'has_archive'        => true,
			'rewrite'            => array('slug' => 'library'),
			'show_in_rest'       => true,
			'menu_icon'          => 'dashicons-book',
			'supports'           => array('title', 'editor', 'thumbnail', 'excerpt'),
		)
	);
}

/**
 * Register taxonomies.
 */
function psymod_library_register_taxonomies(): void
{
	register_taxonomy(
		'material_type',
		PSYMOD_LIBRARY_POST_TYPE,
		array(
			'labels'       => array(
				'name'          => __('Material Types', 'psymod-library'),
				'singular_name' => __('Material Type', 'psymod-library'),
				'menu_name'     => __('Types', 'psymod-library'),
			),
			'hierarchical' => true,
			'show_in_rest' => true,
			'rewrite'      => array('slug' => 'material-type'),
		)
	);

	register_taxonomy(
		'material_category',
		PSYMOD_LIBRARY_POST_TYPE,
		array(
			'labels'       => array(
				'name'          => __('Material Categories', 'psymod-library'),
				'singular_name' => __('Material Category', 'psymod-library'),
				'menu_name'     => __('Categories', 'psymod-library'),
			),
			'hierarchical' => true,
			'show_in_rest' => true,
			'rewrite'      => array('slug' => 'material-category'),
		)
	);
}

/**
 * Default material types for activation.
 */
function psymod_library_get_default_material_types(): array
{
	return array(
		'module'         => 'Module',
		'core'           => 'CORE',
		'pro'            => 'PRO',
		'scenario'       => 'Scenario',
		'target_service' => 'Target service',
		'instruction'    => 'Instruction',
		'page'           => 'Page',
	);
}

/**
 * Default material categories by section for activation.
 *
 * @return array<string, array<string, string>>
 */
function psymod_library_get_default_material_categories_by_section(): array
{
	return array(
		'pro' => array(
			'emotions'                 => 'Эмоции и переживания',
			'self-attitude'            => 'Отношение к себе',
			'relationships'            => 'Отношения с людьми',
			'behavior-scenarios'       => 'Поведение и жизненные сценарии',
			'fears'                    => 'Страхи',
			'control-safety'           => 'Контроль и безопасность',
			'body-psychosomatics'      => 'Тело и психосоматика',
			'love-intimacy-sexuality'  => 'Любовь, близость и сексуальность',
			'meaning-identity'         => 'Смысл и идентичность',
			'money-material-reality'   => 'Деньги и материальная реальность',
		),
	);
}

/**
 * Register default material categories for a section.
 */
function psymod_library_register_default_material_categories(string $section): void
{
	$section = sanitize_key($section);
	$map     = psymod_library_get_default_material_categories_by_section();
	if (! isset($map[$section]) || empty($map[$section])) {
		return;
	}

	foreach ($map[$section] as $slug => $name) {
		if (! term_exists($slug, 'material_category')) {
			wp_insert_term(
				$name,
				'material_category',
				array(
					'slug' => $slug,
				)
			);
		}
	}
}

/**
 * Plugin activation callback.
 */
function psymod_library_activate(): void
{
	// Register CPT and taxonomies before inserting terms.
	psymod_library_register_post_type();
	psymod_library_register_taxonomies();
	psymod_library_register_rewrite_routes();
	psymod_library_register_roles();

	foreach (psymod_library_get_default_material_types() as $slug => $name) {
		if (! term_exists($slug, 'material_type')) {
			wp_insert_term(
				$name,
				'material_type',
				array(
					'slug' => $slug,
				)
			);
		}
	}
	psymod_library_register_default_material_categories('pro');

	flush_rewrite_rules();
}

/**
 * Register MVP user roles for access levels.
 */
function psymod_library_register_roles(): void
{
	add_role(
		'core',
		__('CORE', 'psymod-library'),
		array(
			'read' => true,
		)
	);

	add_role(
		'pro',
		__('PRO', 'psymod-library'),
		array(
			'read' => true,
		)
	);
}

/**
 * Register custom rewrite routes for library sections.
 */
function psymod_library_register_rewrite_routes(): void
{
	add_rewrite_rule('^library/?$', 'index.php?post_type=' . PSYMOD_LIBRARY_POST_TYPE . '&psymod_library_section=all', 'top');
	add_rewrite_rule('^library/(core|pro|scenario|free|modules)/?$', 'index.php?post_type=' . PSYMOD_LIBRARY_POST_TYPE . '&psymod_library_section=$matches[1]', 'top');
	add_rewrite_rule('^library/(pro|scenario)/category/([^/]+)/?$', 'index.php?post_type=' . PSYMOD_LIBRARY_POST_TYPE . '&psymod_library_section=$matches[1]&psymod_library_category=$matches[2]', 'top');
}

/**
 * Register custom query vars.
 */
function psymod_library_register_query_vars(array $vars): array
{
	$vars[] = 'psymod_library_page';
	$vars[] = 'psymod_library_section';
	$vars[] = 'psymod_library_category';
	return $vars;
}

/**
 * Get section config.
 */
function psymod_library_get_archive_sections(): array
{
	return array(
		'all' => array(
			'title'       => 'Библиотека',
			'description' => 'Все материалы PSYMOD в одном месте.',
			'shortcode'   => '[psymod_library]',
			'crumb'       => 'Все материалы',
		),
		'core' => array(
			'title'       => 'CORE',
			'description' => 'Базовые материалы уровня CORE.',
			'shortcode'   => '[psymod_library type="core"]',
			'crumb'       => 'CORE',
		),
		'pro' => array(
			'title'       => 'PRO',
			'description' => 'Продвинутые материалы уровня PRO.',
			'shortcode'   => '[psymod_library type="pro"]',
			'crumb'       => 'PRO',
		),
		'scenario' => array(
			'title'       => 'Сценарии',
			'description' => 'Практические сценарии для работы по системе PSYMOD.',
			'shortcode'   => '[psymod_library type="scenario"]',
			'crumb'       => 'Сценарии',
		),
		'free' => array(
			'title'       => 'Бесплатная подборка',
			'description' => 'Материалы, доступные в бесплатной коллекции.',
			'shortcode'   => '[psymod_library free="1"]',
			'crumb'       => 'Бесплатная подборка',
		),
		'modules' => array(
			'title'       => 'Модули',
			'description' => 'Материалы формата модулей.',
			'shortcode'   => '[psymod_library type="module"]',
			'crumb'       => 'Модули',
		),
	);
}

/**
 * Get archive section URL.
 */
function psymod_library_get_archive_section_url(string $section): string
{
	$section = sanitize_key($section);
	if ($section === 'all') {
		return home_url('/library/');
	}

	return home_url('/library/' . $section . '/');
}

/**
 * Build section shortcode with optional search.
 */
function psymod_library_get_archive_section_shortcode(string $section, string $search_query = '', string $category_slug = '', string $empty_text = ''): string
{
	$section      = sanitize_key($section);
	$search_query = sanitize_text_field($search_query);
	$category_slug = sanitize_title($category_slug);
	$empty_text   = sanitize_text_field($empty_text);
	$search_attr  = $search_query !== '' ? ' search="' . esc_attr($search_query) . '"' : '';
	$category_attr = $category_slug !== '' ? ' category="' . esc_attr($category_slug) . '"' : '';
	$empty_attr   = $empty_text !== '' ? ' empty_text="' . esc_attr($empty_text) . '"' : '';

	if ($section === 'core') {
		return '[psymod_library type="core"' . $search_attr . $category_attr . $empty_attr . ']';
	}
	if ($section === 'pro') {
		return '[psymod_library type="pro"' . $search_attr . $category_attr . $empty_attr . ']';
	}
	if ($section === 'scenario') {
		return '[psymod_library type="scenario"' . $search_attr . $category_attr . $empty_attr . ']';
	}
	if ($section === 'free') {
		return '[psymod_library free="1"' . $search_attr . $category_attr . $empty_attr . ']';
	}
	if ($section === 'modules') {
		return '[psymod_library type="module"' . $search_attr . $category_attr . $empty_attr . ']';
	}

	return '[psymod_library' . $search_attr . $category_attr . $empty_attr . ']';
}

/**
 * Get section category navigation config.
 */
function psymod_library_get_category_navigation_config(string $section): array
{
	$section = sanitize_key($section);

	if ($section === 'pro') {
		return array(
			'enabled'        => true,
			'type_term_slug' => 'pro',
			'category_prefix' => 'pro-',
		);
	}
	if ($section === 'scenario') {
		return array(
			'enabled'        => true,
			'type_term_slug' => 'scenario',
			'category_prefix' => 'scen-',
		);
	}

	return array(
			'enabled'        => false,
			'type_term_slug' => '',
			'category_prefix' => '',
	);
}

/**
 * Get category page URL for section and slug.
 */
function psymod_library_get_category_page_url(string $section, string $slug): string
{
	$section = sanitize_key($section);
	$slug    = sanitize_title($slug);
	return home_url('/library/' . $section . '/category/' . $slug . '/');
}

/**
 * Get category URL by section and term.
 */
function psymod_library_get_category_url(string $section, WP_Term $term): string
{
	return psymod_library_get_category_page_url($section, (string) $term->slug);
}

/**
 * Render breadcrumbs for category page.
 */
function psymod_library_render_category_breadcrumbs(string $section, WP_Term $term): string
{
	$section   = sanitize_key($section);
	$term_id   = (int) $term->term_id;
	$ancestors = array_reverse(get_ancestors($term_id, 'material_category', 'taxonomy'));

	$section_label = $section === 'scenario' ? 'Scenario' : strtoupper($section);

	ob_start();
	?>
	<nav class="psymod-category-breadcrumbs" aria-label="<?php echo esc_attr__('Category breadcrumbs', 'psymod-library'); ?>">
		<a href="<?php echo esc_url(home_url('/library/')); ?>"><?php echo esc_html__('Библиотека', 'psymod-library'); ?></a>
		<span aria-hidden="true">→</span>
		<a href="<?php echo esc_url(psymod_library_get_archive_section_url($section)); ?>"><?php echo esc_html($section_label); ?></a>
		<?php foreach ($ancestors as $ancestor_id) : ?>
			<?php
			$ancestor_term = get_term((int) $ancestor_id, 'material_category');
			if (! $ancestor_term instanceof WP_Term) {
				continue;
			}
			?>
			<span aria-hidden="true">→</span>
			<a href="<?php echo esc_url(psymod_library_get_category_url($section, $ancestor_term)); ?>"><?php echo esc_html($ancestor_term->name); ?></a>
		<?php endforeach; ?>
		<span aria-hidden="true">→</span>
		<span><?php echo esc_html($term->name); ?></span>
	</nav>
	<?php
	return (string) ob_get_clean();
}

/**
 * Render back button for category page.
 */
function psymod_library_render_category_back_button(string $section, WP_Term $term): string
{
	$section    = sanitize_key($section);
	$parent_id  = (int) $term->parent;
	$target_url = psymod_library_get_archive_section_url($section);

	if ($parent_id > 0) {
		$parent_term = get_term($parent_id, 'material_category');
		if ($parent_term instanceof WP_Term) {
			$target_url = psymod_library_get_category_url($section, $parent_term);
		}
	}

	ob_start();
	?>
	<p class="psymod-category-back-wrap">
		<a class="psymod-category-back" href="<?php echo esc_url($target_url); ?>"><?php echo esc_html__('← Назад', 'psymod-library'); ?></a>
	</p>
	<?php
	return (string) ob_get_clean();
}

/**
 * Check if category slug belongs to section prefix.
 */
function psymod_library_is_valid_section_category_slug(string $section, string $slug): bool
{
	$config = psymod_library_get_category_navigation_config($section);
	if (empty($config['enabled'])) {
		return false;
	}

	$slug   = sanitize_title($slug);
	$prefix = (string) $config['category_prefix'];
	return $slug !== '' && $prefix !== '' && strpos($slug, $prefix) === 0;
}

/**
 * Sort terms by numeric prefix in name (1, 1.1, 1.1.1, 10.2.3).
 *
 * @param WP_Term[] $terms
 * @return WP_Term[]
 */
function psymod_library_sort_terms_by_numeric_prefix(array $terms): array
{
	if (count($terms) < 2) {
		return $terms;
	}

	$parse_prefix = static function (string $name): array {
		$name = trim($name);
		if (preg_match('/^(\d+(?:\.\d+)*)/', $name, $matches) !== 1) {
			return array();
		}

		$parts = explode('.', (string) $matches[1]);
		return array_map('intval', $parts);
	};

	usort(
		$terms,
		static function ($a, $b) use ($parse_prefix): int {
			$name_a = $a instanceof WP_Term ? (string) $a->name : '';
			$name_b = $b instanceof WP_Term ? (string) $b->name : '';
			$nums_a = $parse_prefix($name_a);
			$nums_b = $parse_prefix($name_b);
			$has_a  = ! empty($nums_a);
			$has_b  = ! empty($nums_b);

			if ($has_a && $has_b) {
				$max = max(count($nums_a), count($nums_b));
				for ($i = 0; $i < $max; $i++) {
					$part_a = $nums_a[$i] ?? null;
					$part_b = $nums_b[$i] ?? null;
					if ($part_a === $part_b) {
						continue;
					}
					if ($part_a === null) {
						return -1;
					}
					if ($part_b === null) {
						return 1;
					}
					return $part_a <=> $part_b;
				}
			}

			if ($has_a && ! $has_b) {
				return -1;
			}
			if (! $has_a && $has_b) {
				return 1;
			}

			return strcasecmp($name_a, $name_b);
		}
	);

	return array_values($terms);
}

/**
 * Get section categories by parent.
 *
 * @return WP_Term[]
 */
function psymod_library_get_section_categories(string $section, int $parent_id = 0): array
{
	$config = psymod_library_get_category_navigation_config($section);
	if (empty($config['enabled'])) {
		return array();
	}

	$terms = get_terms(
		array(
			'taxonomy'   => 'material_category',
			'hide_empty' => false,
			'parent'     => $parent_id,
			'orderby'    => 'name',
			'order'      => 'ASC',
		)
	);
	if (is_wp_error($terms) || empty($terms)) {
		return array();
	}

	$prefix = (string) $config['category_prefix'];
	$terms  = array_values(
		array_filter(
			$terms,
			static function ($term) use ($prefix): bool {
				return $term instanceof WP_Term && strpos((string) $term->slug, $prefix) === 0;
			}
		)
	);

	return psymod_library_sort_terms_by_numeric_prefix($terms);
}

/**
 * Count materials in category limited by section material_type.
 */
function psymod_library_get_section_category_material_count(string $section, int $term_id): int
{
	$config = psymod_library_get_category_navigation_config($section);
	if (empty($config['enabled'])) {
		return 0;
	}

	$children_ids = get_term_children($term_id, 'material_category');
	if (is_wp_error($children_ids)) {
		$children_ids = array();
	}
	$term_ids = array_map('absint', array_merge(array($term_id), is_array($children_ids) ? $children_ids : array()));
	$term_ids = array_values(array_unique(array_filter($term_ids)));
	if (empty($term_ids)) {
		return 0;
	}

	$query = new WP_Query(
		array(
			'post_type'      => PSYMOD_LIBRARY_POST_TYPE,
			'post_status'    => 'publish',
			'posts_per_page' => 1,
			'fields'         => 'ids',
			'tax_query'      => array(
				'relation' => 'AND',
				array(
					'taxonomy' => 'material_type',
					'field'    => 'slug',
					'terms'    => array((string) $config['type_term_slug']),
				),
				array(
					'taxonomy'         => 'material_category',
					'field'            => 'term_id',
					'terms'            => $term_ids,
					'include_children' => false,
				),
			),
		)
	);

	return (int) $query->found_posts;
}

/**
 * Render category cards list.
 *
 * @param WP_Term[] $terms
 */
function psymod_library_render_section_category_cards(string $section, array $terms, bool $vertical = false): string
{
	unset($vertical);

	if (empty($terms)) {
		return '';
	}

	ob_start();
	?>
	<div class="psymod-category-grid">
		<?php foreach ($terms as $term) : ?>
			<?php if (! $term instanceof WP_Term) {
				continue;
			} ?>
			<a class="psymod-category-grid__card" href="<?php echo esc_url(psymod_library_get_category_page_url($section, (string) $term->slug)); ?>">
				<div class="psymod-category-grid__name"><?php echo esc_html($term->name); ?></div>
				<div class="psymod-category-grid__meta">
					<span class="psymod-category-grid__count"><?php echo esc_html((string) psymod_library_get_section_category_material_count($section, (int) $term->term_id)); ?></span>
				</div>
				<?php if ((string) $term->description !== '') : ?>
					<p class="psymod-category-grid__desc"><?php echo esc_html(wp_strip_all_tags((string) $term->description)); ?></p>
				<?php endif; ?>
			</a>
		<?php endforeach; ?>
	</div>
	<?php
	return (string) ob_get_clean();
}

/**
 * Render search form for archive section.
 */
function psymod_library_render_search_form(string $section, string $category_slug = ''): string
{
	$section      = sanitize_key($section);
	$category_slug = sanitize_title($category_slug);
	$section_url  = $category_slug !== '' ? psymod_library_get_category_page_url($section, $category_slug) : psymod_library_get_archive_section_url($section);
	$search_query = isset($_GET['psymod_search']) ? sanitize_text_field(wp_unslash($_GET['psymod_search'])) : '';

	ob_start();
	?>
	<form class="psymod-library-search" method="get" action="<?php echo esc_url($section_url); ?>">
		<div class="psymod-library-search__row">
			<input class="psymod-library-search__input" type="search" name="psymod_search" value="<?php echo esc_attr($search_query); ?>" placeholder="<?php echo esc_attr__('Поиск по библиотеке', 'psymod-library'); ?>">
			<button class="psymod-library-search__button" type="submit"><?php echo esc_html__('Найти', 'psymod-library'); ?></button>
		</div>
	</form>
	<?php if ($search_query !== '') : ?>
		<div class="psymod-library-search__summary">
			<span><?php echo esc_html(sprintf(__('Результаты поиска: %s', 'psymod-library'), $search_query)); ?></span>
			<a href="<?php echo esc_url($section_url); ?>"><?php echo esc_html__('Сбросить поиск', 'psymod-library'); ?></a>
		</div>
	<?php endif; ?>
	<?php

	return (string) ob_get_clean();
}

/**
 * Render custom archive page.
 */
function psymod_library_render_archive_page(string $section): string
{
	$sections = psymod_library_get_archive_sections();
	$section  = sanitize_key($section);
	if (! isset($sections[$section])) {
		$section = 'all';
	}

	$current      = $sections[$section];
	$library_url  = home_url('/library/');
	$search_query = isset($_GET['psymod_search']) ? sanitize_text_field(wp_unslash($_GET['psymod_search'])) : '';
	$category_slug = sanitize_title((string) get_query_var('psymod_library_category', ''));
	$config       = psymod_library_get_category_navigation_config($section);
	$is_category_section = ! empty($config['enabled']);
	$is_category_route   = $category_slug !== '';
	$category_term = null;
	if ($category_slug !== '' && psymod_library_is_valid_section_category_slug($section, $category_slug)) {
		$candidate_term = get_term_by('slug', $category_slug, 'material_category');
		if ($candidate_term instanceof WP_Term) {
			$category_term = $candidate_term;
		}
	}

	ob_start();
	?>
	<div class="psymod-library-archive">
		<nav class="psymod-library-breadcrumbs" aria-label="<?php echo esc_attr__('Breadcrumbs', 'psymod-library'); ?>">
			<a href="<?php echo esc_url($library_url); ?>"><?php echo esc_html__('Библиотека', 'psymod-library'); ?></a>
			<span aria-hidden="true">→</span>
			<span><?php echo esc_html($current['crumb']); ?></span>
		</nav>

		<section class="psymod-library-hero">
			<h1 class="psymod-library-hero__title"><?php echo esc_html($current['title']); ?></h1>
			<p class="psymod-library-hero__description"><?php echo esc_html($current['description']); ?></p>
			<?php if ($section === 'modules') : ?>
				<?php $modules_guide_url = apply_filters('psymod_library_modules_guide_url', home_url('/library/modules-guide/')); ?>
				<p class="psymod-library-hero__cta-wrap">
					<a class="psymod-library-hero__cta" href="<?php echo esc_url((string) $modules_guide_url); ?>">
						<?php echo esc_html__('Инструкция по установке и работе с модулями', 'psymod-library'); ?>
					</a>
				</p>
			<?php endif; ?>
		</section>
		<?php echo psymod_library_render_library_tabs($section); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		<?php echo psymod_library_render_search_form($section, $category_term instanceof WP_Term ? (string) $category_term->slug : ''); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		<?php if ($is_category_route) : ?>
			<!-- PSYMOD CATEGORY ROUTE HIT -->
		<?php endif; ?>

		<?php if (! $is_category_section) : ?>
			<div class="psymod-library-archive__grid">
				<?php echo do_shortcode(psymod_library_get_archive_section_shortcode($section, $search_query)); ?>
			</div>
		<?php elseif (! ($category_term instanceof WP_Term)) : ?>
			<?php
			if ($is_category_route) {
				echo psymod_library_render_empty_state('', 'В этой категории пока нет материалов.'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			} else {
				$top_categories = psymod_library_get_section_categories($section, 0);
				if (! empty($top_categories)) {
					echo psymod_library_render_section_category_cards($section, $top_categories, false); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				} else {
					echo psymod_library_render_empty_state('', 'В этом разделе пока нет категорий.'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				}
			}
			?>
		<?php else : ?>
			<?php
			echo "\n<!-- PSYMOD CATEGORY TERM FOUND -->\n";
			if ($section === 'pro') {
				echo "\n<!-- PSYMOD PRO CATEGORY PAGE -->\n";
			}
			if ($section === 'scenario') {
				echo "\n<!-- PSYMOD SCENARIO CATEGORY PAGE -->\n";
			}
			$child_categories = psymod_library_get_section_categories($section, (int) $category_term->term_id);
			echo "\n<!-- PSYMOD CATEGORY CHILDREN COUNT: " . esc_html((string) count($child_categories)) . " -->\n";
			if (current_user_can('manage_options')) {
				$debug_query_args_with_both = array(
					'post_type'      => PSYMOD_LIBRARY_POST_TYPE,
					'post_status'    => 'publish',
					'posts_per_page' => 1,
					'fields'         => 'ids',
					'tax_query'      => array(
						'relation' => 'AND',
						array(
							'taxonomy' => 'material_type',
							'field'    => 'slug',
							'terms'    => array((string) $config['type_term_slug']),
						),
						array(
							'taxonomy'         => 'material_category',
							'field'            => 'term_id',
							'terms'            => array((int) $category_term->term_id),
							'include_children' => true,
						),
					),
				);
				if ($search_query !== '') {
					$debug_query_args_with_both['psymod_library_search_ext'] = $search_query;
				}

				$debug_query_args_without_type = array(
					'post_type'      => PSYMOD_LIBRARY_POST_TYPE,
					'post_status'    => 'publish',
					'posts_per_page' => 1,
					'fields'         => 'ids',
					'tax_query'      => array(
						array(
							'taxonomy'         => 'material_category',
							'field'            => 'term_id',
							'terms'            => array((int) $category_term->term_id),
							'include_children' => true,
						),
					),
				);
				if ($search_query !== '') {
					$debug_query_args_without_type['psymod_library_search_ext'] = $search_query;
				}

				$debug_query_args_without_category = array(
					'post_type'      => PSYMOD_LIBRARY_POST_TYPE,
					'post_status'    => 'publish',
					'posts_per_page' => 1,
					'fields'         => 'ids',
					'tax_query'      => array(
						array(
							'taxonomy' => 'material_type',
							'field'    => 'slug',
							'terms'    => array((string) $config['type_term_slug']),
						),
					),
				);
				if ($search_query !== '') {
					$debug_query_args_without_category['psymod_library_search_ext'] = $search_query;
				}

				$debug_query_with_both = new WP_Query($debug_query_args_with_both);
				$debug_query_without_type = new WP_Query($debug_query_args_without_type);
				$debug_query_without_category = new WP_Query($debug_query_args_without_category);
				$debug_args_export = array(
					'post_type' => $debug_query_args_with_both['post_type'],
					'tax_query' => $debug_query_args_with_both['tax_query'],
				);

				echo "\n<!-- PSYMOD DEBUG section=" . esc_html($section)
					. " type=" . esc_html((string) $config['type_term_slug'])
					. " category_id=" . esc_html((string) $category_term->term_id)
					. " category_slug=" . esc_html((string) $category_term->slug)
					. " category_name=" . esc_html((string) $category_term->name)
					. " category_taxonomy=" . esc_html((string) $category_term->taxonomy)
					. " found_with_both=" . esc_html((string) $debug_query_with_both->found_posts)
					. " found_without_type=" . esc_html((string) $debug_query_without_type->found_posts)
					. " found_without_category=" . esc_html((string) $debug_query_without_category->found_posts)
					. " -->\n";
				echo "\n<!-- PSYMOD DEBUG query_args=" . esc_html((string) wp_json_encode($debug_args_export)) . " -->\n";
			}
			?>
			<?php echo psymod_library_render_category_breadcrumbs($section, $category_term); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php echo psymod_library_render_category_back_button($section, $category_term); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php if (! empty($child_categories)) : ?>
				<?php echo psymod_library_render_section_category_cards($section, $child_categories, true); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php else : ?>
				<!-- PSYMOD CATEGORY MATERIALS RENDER -->
				<!-- PSYMOD MATERIAL LIST -->
				<div class="psymod-library-archive__grid">
					<?php echo do_shortcode(psymod_library_get_archive_section_shortcode($section, $search_query, (string) $category_term->slug, 'В этой категории пока нет материалов.')); ?>
				</div>
			<?php endif; ?>
		<?php endif; ?>
	</div>
	<?php

	return (string) ob_get_clean();
}

/**
 * Render library archive tabs.
 */
function psymod_library_render_library_tabs(string $active_section): string
{
	$active_section = sanitize_key($active_section);
	$tabs           = array(
		'all'      => array('label' => 'Все материалы', 'url' => home_url('/library/')),
		'modules'  => array('label' => 'Модули', 'url' => home_url('/library/modules/')),
		'core'     => array('label' => 'CORE', 'url' => home_url('/library/core/')),
		'pro'      => array('label' => 'PRO', 'url' => home_url('/library/pro/')),
		'scenario' => array('label' => 'Scenario', 'url' => home_url('/library/scenario/')),
		'free'     => array('label' => 'Бесплатные', 'url' => home_url('/library/free/')),
	);

	ob_start();
	?>
	<nav class="psymod-library-tabs" aria-label="<?php echo esc_attr__('Library sections', 'psymod-library'); ?>">
		<?php foreach ($tabs as $key => $tab) : ?>
			<?php $is_active = $active_section === $key; ?>
			<a
				class="psymod-library-tab<?php echo $is_active ? ' is-active' : ''; ?>"
				href="<?php echo esc_url($tab['url']); ?>"
				<?php echo $is_active ? 'aria-current="page"' : ''; ?>
			>
				<?php echo esc_html($tab['label']); ?>
			</a>
		<?php endforeach; ?>
	</nav>
	<?php

	return (string) ob_get_clean();
}

/**
 * Render archive sections on matched routes.
 */
function psymod_library_maybe_render_archive_page(): void
{
	$section = get_query_var('psymod_library_section', '');

	// Fallback: force unified library renderer for /library/{section}/ URLs even if a page with same path exists.
	if ($section === '') {
		$request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
		$path        = trim((string) wp_parse_url($request_uri, PHP_URL_PATH), '/');

		// Support prefixed paths too (e.g. /ru/library/modules/).
		if (preg_match('#(?:^|/)library/(core|pro|scenario|free|modules)(?:/|$)#i', $path, $matches) === 1 && ! empty($matches[1])) {
			$section = sanitize_key((string) $matches[1]);
		}
	}

	if ($section === '' && ! is_post_type_archive(PSYMOD_LIBRARY_POST_TYPE)) {
		return;
	}

	if ($section === '') {
		$section = 'all';
	}

	$sections = psymod_library_get_archive_sections();
	if (! isset($sections[$section])) {
		$section = 'all';
	}

	status_header(200);
	get_header();
	echo psymod_library_render_archive_page($section); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	get_footer();
	exit;
}

/**
 * Check whether current query is PSYMOD extended search.
 */
function psymod_library_is_extended_search_query(WP_Query $query): bool
{
	$search_query = (string) $query->get('psymod_library_search_ext', '');
	if ($search_query === '') {
		return false;
	}

	$post_type = $query->get('post_type');
	if (is_array($post_type)) {
		return in_array(PSYMOD_LIBRARY_POST_TYPE, $post_type, true);
	}

	return $post_type === PSYMOD_LIBRARY_POST_TYPE;
}

/**
 * Join meta and taxonomy tables for extended library search.
 */
function psymod_library_search_posts_join(string $join, WP_Query $query): string
{
	if (! psymod_library_is_extended_search_query($query)) {
		return $join;
	}

	global $wpdb;

	$join .= " LEFT JOIN {$wpdb->postmeta} AS psl_pm ON ({$wpdb->posts}.ID = psl_pm.post_id AND psl_pm.meta_key = 'short_description')";
	$join .= " LEFT JOIN {$wpdb->term_relationships} AS psl_tr ON ({$wpdb->posts}.ID = psl_tr.object_id)";
	$join .= " LEFT JOIN {$wpdb->term_taxonomy} AS psl_tt ON (psl_tr.term_taxonomy_id = psl_tt.term_taxonomy_id AND psl_tt.taxonomy IN ('material_type','material_category'))";
	$join .= " LEFT JOIN {$wpdb->terms} AS psl_t ON (psl_tt.term_id = psl_t.term_id)";

	return $join;
}

/**
 * Add extended search conditions for title/content/meta/terms.
 */
function psymod_library_search_posts_where(string $where, WP_Query $query): string
{
	if (! psymod_library_is_extended_search_query($query)) {
		return $where;
	}

	global $wpdb;

	$raw_search = (string) $query->get('psymod_library_search_ext', '');
	$search     = sanitize_text_field($raw_search);
	if ($search === '') {
		return $where;
	}

	$like      = '%' . $wpdb->esc_like($search) . '%';
	$condition = $wpdb->prepare(
		" AND (
			{$wpdb->posts}.post_title LIKE %s
			OR {$wpdb->posts}.post_content LIKE %s
			OR psl_pm.meta_value LIKE %s
			OR psl_t.name LIKE %s
			OR psl_t.slug LIKE %s
		)",
		$like,
		$like,
		$like,
		$like,
		$like
	);

	return $where . $condition;
}

/**
 * Prevent duplicates due to extra joins.
 */
function psymod_library_search_posts_distinct(string $distinct, WP_Query $query): string
{
	if (! psymod_library_is_extended_search_query($query)) {
		return $distinct;
	}

	return 'DISTINCT';
}

/**
 * Render empty state for library shortcode.
 */
function psymod_library_render_empty_state(string $search_query = '', string $custom_text = ''): string
{
	$search_query = sanitize_text_field($search_query);
	$custom_text  = sanitize_text_field($custom_text);
	$library_url  = home_url('/library/');

	ob_start();
	?>
	<div class="psymod-library-empty-state">
		<h3 class="psymod-library-empty-state__title"><?php echo esc_html__('Материалы пока не добавлены', 'psymod-library'); ?></h3>
		<p class="psymod-library-empty-state__text">
			<?php
			if ($custom_text !== '') {
				echo esc_html($custom_text);
			} elseif ($search_query !== '') {
				echo esc_html__('По вашему запросу ничего не найдено.', 'psymod-library');
			} else {
				echo esc_html__('В этом разделе пока нет опубликованных материалов.', 'psymod-library');
			}
			?>
		</p>
		<p class="psymod-library-empty-state__actions">
			<a class="psymod-library-empty-state__link" href="<?php echo esc_url($library_url); ?>"><?php echo esc_html__('Вернуться ко всем материалам', 'psymod-library'); ?></a>
		</p>
	</div>
	<?php

	return (string) ob_get_clean();
}

/**
 * Register post meta fields.
 */
function psymod_library_register_meta_fields(): void
{
	register_post_meta(
		PSYMOD_LIBRARY_POST_TYPE,
		'short_description',
		array(
			'type'              => 'string',
			'single'            => true,
			'sanitize_callback' => 'sanitize_textarea_field',
			'show_in_rest'      => true,
			'auth_callback'     => static function () {
				return current_user_can('edit_posts');
			},
		)
	);

	register_post_meta(
		PSYMOD_LIBRARY_POST_TYPE,
		'required_access_level',
		array(
			'type'              => 'string',
			'single'            => true,
			'sanitize_callback' => 'psymod_library_sanitize_access_level',
			'show_in_rest'      => true,
			'auth_callback'     => static function () {
				return current_user_can('edit_posts');
			},
		)
	);

	register_post_meta(
		PSYMOD_LIBRARY_POST_TYPE,
		'reading_time',
		array(
			'type'              => 'integer',
			'single'            => true,
			'sanitize_callback' => 'absint',
			'show_in_rest'      => true,
			'auth_callback'     => static function () {
				return current_user_can('edit_posts');
			},
		)
	);

	register_post_meta(
		PSYMOD_LIBRARY_POST_TYPE,
		'is_in_free_collection',
		array(
			'type'              => 'boolean',
			'single'            => true,
			'sanitize_callback' => 'rest_sanitize_boolean',
			'show_in_rest'      => true,
			'auth_callback'     => static function () {
				return current_user_can('edit_posts');
			},
		)
	);

	register_post_meta(
		PSYMOD_LIBRARY_POST_TYPE,
		'material_order',
		array(
			'type'              => 'integer',
			'single'            => true,
			'sanitize_callback' => 'absint',
			'show_in_rest'      => true,
			'auth_callback'     => static function () {
				return current_user_can('edit_posts');
			},
		)
	);

	register_post_meta(
		PSYMOD_LIBRARY_POST_TYPE,
		'related_materials',
		array(
			'type'              => 'array',
			'single'            => true,
			'sanitize_callback' => 'psymod_library_sanitize_related_materials',
			'show_in_rest'      => false,
			'auth_callback'     => static function () {
				return current_user_can('edit_posts');
			},
		)
	);
}

/**
 * Register meta box for material fields.
 */
function psymod_library_register_meta_box(): void
{
	add_meta_box(
		'psymod_library_material_meta',
		__('Material Details', 'psymod-library'),
		'psymod_library_render_meta_box',
		PSYMOD_LIBRARY_POST_TYPE,
		'normal',
		'default'
	);
}

/**
 * Render meta box.
 */
function psymod_library_render_meta_box(WP_Post $post): void
{
	wp_nonce_field('psymod_library_save_meta', PSYMOD_LIBRARY_NONCE_KEY);

	$short_description    = get_post_meta($post->ID, 'short_description', true);
	$required_access      = psymod_library_sanitize_access_level(get_post_meta($post->ID, 'required_access_level', true));
	$reading_time         = (int) get_post_meta($post->ID, 'reading_time', true);
	$material_order       = (int) get_post_meta($post->ID, 'material_order', true);
	$related_materials    = psymod_library_sanitize_related_materials(get_post_meta($post->ID, 'related_materials', true));
	$related_materials_ui = implode(', ', $related_materials);
	$is_in_free_selection = (bool) get_post_meta($post->ID, 'is_in_free_collection', true);
	$access_labels        = psymod_library_get_access_level_labels();
	?>
	<p>
		<label for="psymod_short_description"><strong><?php esc_html_e('Short Description', 'psymod-library'); ?></strong></label>
		<textarea id="psymod_short_description" name="short_description" rows="4" style="width:100%;"><?php echo esc_textarea($short_description); ?></textarea>
	</p>

	<p>
		<label for="psymod_required_access_level"><strong><?php esc_html_e('Required Access Level', 'psymod-library'); ?></strong></label>
		<select id="psymod_required_access_level" name="required_access_level" style="width:100%;">
			<?php foreach ($access_labels as $access_value => $access_label) : ?>
				<option value="<?php echo esc_attr($access_value); ?>" <?php selected($required_access, $access_value); ?>>
					<?php echo esc_html($access_label); ?>
				</option>
			<?php endforeach; ?>
		</select>
	</p>

	<p>
		<label for="psymod_reading_time"><strong><?php esc_html_e('Reading Time (minutes)', 'psymod-library'); ?></strong></label>
		<input id="psymod_reading_time" name="reading_time" type="number" min="0" value="<?php echo esc_attr((string) $reading_time); ?>" style="width:100%;">
	</p>

	<p>
		<label for="psymod_material_order"><strong><?php esc_html_e('Order / Порядок вывода', 'psymod-library'); ?></strong></label>
		<input id="psymod_material_order" name="material_order" type="number" min="0" value="<?php echo esc_attr((string) $material_order); ?>" style="width:100%;">
	</p>

	<p>
		<label for="psymod_related_materials"><strong><?php esc_html_e('Related materials / Связанные материалы', 'psymod-library'); ?></strong></label>
		<textarea id="psymod_related_materials" name="related_materials" rows="3" style="width:100%;" placeholder="<?php echo esc_attr__('123, 124, 130', 'psymod-library'); ?>"><?php echo esc_textarea($related_materials_ui); ?></textarea>
	</p>

	<p>
		<label for="psymod_is_in_free_collection">
			<input id="psymod_is_in_free_collection" name="is_in_free_collection" type="checkbox" value="1" <?php checked($is_in_free_selection); ?>>
			<?php esc_html_e('Included in free collection', 'psymod-library'); ?>
		</label>
	</p>
	<?php
}

/**
 * Save meta fields.
 */
function psymod_library_save_meta_fields(int $post_id): void
{
	if (! isset($_POST[PSYMOD_LIBRARY_NONCE_KEY]) || ! wp_verify_nonce(sanitize_text_field(wp_unslash($_POST[PSYMOD_LIBRARY_NONCE_KEY])), 'psymod_library_save_meta')) {
		return;
	}

	if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
		return;
	}

	if (! current_user_can('edit_post', $post_id)) {
		return;
	}

	$short_description = isset($_POST['short_description']) ? sanitize_textarea_field(wp_unslash($_POST['short_description'])) : '';
	$required_access   = isset($_POST['required_access_level']) ? psymod_library_sanitize_access_level(wp_unslash($_POST['required_access_level'])) : 'public';
	$reading_time      = isset($_POST['reading_time']) ? absint(wp_unslash($_POST['reading_time'])) : 0;
	$material_order    = isset($_POST['material_order']) ? absint(wp_unslash($_POST['material_order'])) : 0;
	$related_materials = isset($_POST['related_materials']) ? psymod_library_sanitize_related_materials(wp_unslash($_POST['related_materials'])) : array();
	$is_free           = isset($_POST['is_in_free_collection']) ? true : false;

	update_post_meta($post_id, 'short_description', $short_description);
	update_post_meta($post_id, 'required_access_level', $required_access);
	update_post_meta($post_id, 'reading_time', $reading_time);
	update_post_meta($post_id, 'material_order', $material_order);
	update_post_meta($post_id, 'related_materials', $related_materials);
	update_post_meta($post_id, 'is_in_free_collection', $is_free);
}

/**
 * Get card CTA button label by access state.
 */
function psymod_library_get_card_button_label(int $post_id): string
{
	$access_level = psymod_library_sanitize_access_level(get_post_meta($post_id, 'required_access_level', true));

	if ($access_level === 'public') {
		return 'Читать';
	}

	if (psymod_library_user_has_access($post_id)) {
		return 'Открыть материал';
	}

	return 'Получить доступ';
}

/**
 * Get badge class for access level.
 */
function psymod_library_get_access_badge_class(string $access_level): string
{
	$access_level = psymod_library_sanitize_access_level($access_level);
	return 'psymod-badge--' . sanitize_html_class($access_level);
}

/**
 * Get first material type label.
 */
function psymod_library_get_material_type_label(int $post_id): string
{
	$terms = get_the_terms($post_id, 'material_type');
	if (is_wp_error($terms) || empty($terms)) {
		return '';
	}

	$term = reset($terms);
	if (! $term instanceof WP_Term) {
		return '';
	}

	return (string) $term->name;
}

/**
 * Render library card.
 */
function psymod_library_render_material_card(int $post_id): string
{
	$title             = get_the_title($post_id);
	$permalink         = get_permalink($post_id);
	$short_description = get_post_meta($post_id, 'short_description', true);
	$reading_time      = (int) get_post_meta($post_id, 'reading_time', true);
	$access_level      = psymod_library_sanitize_access_level(get_post_meta($post_id, 'required_access_level', true));
	$access_labels     = psymod_library_get_access_level_labels();
	$access_label      = isset($access_labels[$access_level]) ? $access_labels[$access_level] : $access_labels['public'];
	$access_badge      = psymod_library_get_access_badge_class($access_level);
	$is_free           = (bool) get_post_meta($post_id, 'is_in_free_collection', true);
	$button_label      = psymod_library_get_card_button_label($post_id);

	ob_start();
	?>
	<article class="psymod-material-card" style="background:#fff;border-radius:18px;overflow:hidden;">
		<?php if (has_post_thumbnail($post_id)) : ?>
			<div class="psymod-material-card__thumb" style="overflow:hidden;">
				<a href="<?php echo esc_url($permalink); ?>">
					<?php
					echo get_the_post_thumbnail(
						$post_id,
						'medium_large',
						array(
							'style' => 'display:block;width:100%;height:100%;max-width:none;object-fit:cover;',
						)
					);
					?>
				</a>
			</div>
		<?php endif; ?>

		<div class="psymod-material-card__content">
			<h3 class="psymod-material-card__title">
				<a href="<?php echo esc_url($permalink); ?>"><?php echo esc_html($title); ?></a>
			</h3>

			<?php if (! empty($short_description)) : ?>
				<p class="psymod-material-card__description"><?php echo esc_html($short_description); ?></p>
			<?php elseif (has_excerpt($post_id)) : ?>
				<p class="psymod-material-card__description"><?php echo esc_html(get_the_excerpt($post_id)); ?></p>
			<?php endif; ?>

			<div class="psymod-material-card__meta">
				<?php if ($reading_time > 0) : ?>
					<span class="psymod-material-card__reading-time"><?php echo esc_html(sprintf(__('%d min read', 'psymod-library'), $reading_time)); ?></span>
				<?php endif; ?>
			</div>
			<div class="psymod-material-card__badges">
				<span class="psymod-badge <?php echo esc_attr($access_badge); ?>"><?php echo esc_html($access_label); ?></span>
				<?php if ($is_free) : ?><span class="psymod-badge psymod-badge--free"><?php esc_html_e('Free', 'psymod-library'); ?></span><?php endif; ?>
			</div>
			<p class="psymod-material-card__cta-wrap">
				<a class="psymod-material-card__cta" href="<?php echo esc_url($permalink); ?>">
					<?php echo esc_html($button_label); ?>
				</a>
			</p>
		</div>
	</article>
	<?php
	return (string) ob_get_clean();
}

/**
 * Check whether current user can access full material content.
 */
function psymod_library_user_has_access(int $post_id): bool
{
	$access_level = psymod_library_sanitize_access_level(get_post_meta($post_id, 'required_access_level', true));

	if ($access_level === 'public') {
		return true;
	}

	$user         = wp_get_current_user();
	$user_level   = psymod_library_get_user_access_level($user instanceof WP_User ? (int) $user->ID : 0);

	// Administrator and Editor always have full access (mapped to admin_only).
	if ($user_level === 'admin_only') {
		return true;
	}

	if ($access_level === 'free_user') {
		return $user_level !== 'guest';
	}

	if ($access_level === 'core') {
		return $user_level === 'core' || $user_level === 'pro';
	}

	if ($access_level === 'pro') {
		return $user_level === 'pro';
	}

	if ($access_level === 'admin_only') {
		return $user_level === 'admin_only';
	}

	return false;
}

/**
 * Get normalized PSYMOD Library access level for a user.
 *
 * @return string guest|free_user|core|pro|admin_only
 */
function psymod_library_get_user_access_level(int $user_id): string
{
	$user_id = absint($user_id);
	if ($user_id <= 0) {
		return 'guest';
	}

	$user = get_userdata($user_id);
	if (! ($user instanceof WP_User)) {
		return 'guest';
	}

	$roles = (array) $user->roles;

	if (in_array('administrator', $roles, true) || in_array('editor', $roles, true)) {
		return 'admin_only';
	}

	if (in_array('pro', $roles, true)) {
		return 'pro';
	}

	if (in_array('core', $roles, true)) {
		return 'core';
	}

	return is_user_logged_in() ? 'free_user' : 'guest';
}

/**
 * Get adjacent material post by publish date.
 */
function psymod_library_get_adjacent_material(int $post_id, string $direction): ?WP_Post
{
	$post = get_post($post_id);
	if (! ($post instanceof WP_Post) || $post->post_type !== PSYMOD_LIBRARY_POST_TYPE) {
		return null;
	}

	$is_prev   = $direction === 'prev';
	$date_args = $is_prev
		? array('before' => $post->post_date_gmt)
		: array('after' => $post->post_date_gmt);

	$posts = get_posts(
		array(
			'post_type'      => PSYMOD_LIBRARY_POST_TYPE,
			'post_status'    => 'publish',
			'posts_per_page' => 1,
			'post__not_in'   => array($post_id),
			'orderby'        => 'date',
			'order'          => $is_prev ? 'DESC' : 'ASC',
			'date_query'     => array(
				array_merge(
					array(
						'column'    => 'post_date_gmt',
						'inclusive' => false,
					),
					$date_args
				),
			),
		)
	);

	if (empty($posts) || ! isset($posts[0]) || ! ($posts[0] instanceof WP_Post)) {
		return null;
	}

	return $posts[0];
}

/**
 * Render single material navigation item.
 */
function psymod_library_render_single_navigation_item(?WP_Post $post, string $direction): string
{
	$direction = $direction === 'prev' ? 'prev' : 'next';
	if (! ($post instanceof WP_Post)) {
		return '<div class="psymod-single-nav__item is-empty" aria-hidden="true"></div>';
	}

	$label = $direction === 'prev' ? 'НАЗАД' : 'ДАЛЕЕ';
	$arrow = $direction === 'prev' ? '←' : '→';

	ob_start();
	?>
	<a class="psymod-single-nav__item psymod-single-nav__item--<?php echo esc_attr($direction); ?>" href="<?php echo esc_url(get_permalink($post->ID)); ?>">
		<span class="psymod-single-nav__icon" aria-hidden="true"><?php echo esc_html($arrow); ?></span>
		<span class="psymod-single-nav__text">
			<span class="psymod-single-nav__label"><?php echo esc_html($label); ?></span>
			<span class="psymod-single-nav__title"><?php echo esc_html(get_the_title($post->ID)); ?></span>
		</span>
	</a>
	<?php

	return (string) ob_get_clean();
}

/**
 * Render prev/next navigation section for single material pages.
 */
function psymod_library_render_single_material_navigation(int $post_id): string
{
	$prev_post = psymod_library_get_adjacent_material($post_id, 'prev');
	$next_post = psymod_library_get_adjacent_material($post_id, 'next');

	if (! $prev_post && ! $next_post) {
		return '';
	}

	ob_start();
	?>
	<section class="psymod-single-nav" aria-label="<?php echo esc_attr__('Material navigation', 'psymod-library'); ?>">
		<div class="psymod-single-nav__grid">
			<?php echo psymod_library_render_single_navigation_item($prev_post, 'prev'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<div class="psymod-single-nav__divider" aria-hidden="true"></div>
			<?php echo psymod_library_render_single_navigation_item($next_post, 'next'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		</div>
	</section>
	<?php

	return (string) ob_get_clean();
}

/**
 * Filter protected content for library materials.
 */
function psymod_library_filter_protected_content(string $content): string
{
	if (is_admin() || ! is_singular(PSYMOD_LIBRARY_POST_TYPE) || ! in_the_loop() || ! is_main_query()) {
		return $content;
	}

	$post_id = get_the_ID();
	if (! $post_id) {
		return $content;
	}

	$access_level = psymod_library_sanitize_access_level(get_post_meta($post_id, 'required_access_level', true));
	$labels       = psymod_library_get_access_level_labels();
	$access_label = isset($labels[$access_level]) ? $labels[$access_level] : $labels['public'];
	$access_badge = psymod_library_get_access_badge_class($access_level);
	$type_label   = psymod_library_get_material_type_label((int) $post_id);
	$reading_time = (int) get_post_meta($post_id, 'reading_time', true);
	$library_url  = get_post_type_archive_link(PSYMOD_LIBRARY_POST_TYPE);
	if (! is_string($library_url) || $library_url === '') {
		$library_url = home_url('/library/');
	}
	$navigation_html = psymod_library_render_single_material_navigation((int) $post_id);

	ob_start();
	?>
	<div class="psymod-single-material-container">
	<div class="psymod-single-material">
		<?php if (has_post_thumbnail((int) $post_id)) : ?>
			<div class="psymod-single-material__hero">
				<?php echo get_the_post_thumbnail((int) $post_id, 'full'); ?>
			</div>
		<?php endif; ?>
		<div class="psymod-single-material__meta">
			<span class="psymod-badge <?php echo esc_attr($access_badge); ?>"><?php echo esc_html($access_label); ?></span>
			<?php if ($type_label !== '') : ?>
				<span class="psymod-badge psymod-badge--type"><?php echo esc_html($type_label); ?></span>
			<?php endif; ?>
			<?php if ($reading_time > 0) : ?>
				<span class="psymod-single-material__reading-time"><?php echo esc_html(sprintf(__('%d min read', 'psymod-library'), $reading_time)); ?></span>
			<?php endif; ?>
		</div>
	<?php

	if ($access_level === 'public' || psymod_library_user_has_access((int) $post_id)) {
		?>
		<div class="psymod-single-material__content"><?php echo $content; ?></div>
		<?php echo psymod_library_render_related_materials((int) $post_id); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		<p class="psymod-single-material__back-wrap">
			<a class="psymod-single-material__back" href="<?php echo esc_url($library_url); ?>"><?php echo esc_html__('← Назад в библиотеку', 'psymod-library'); ?></a>
		</p>
		<?php echo $navigation_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
	</div>
	</div>
		<?php
		return (string) ob_get_clean();
	}

	$get_access   = apply_filters('psymod_library_get_access_url', wp_login_url(get_permalink((int) $post_id)), (int) $post_id);
	$compare_url  = apply_filters('psymod_library_compare_access_url', home_url('/access-levels/'), (int) $post_id);
	?>
	<div class="psymod-library-lock psymod-library-lock--single">
		<h3 class="psymod-library-lock__title"><?php echo esc_html__('Материал закрыт', 'psymod-library'); ?></h3>
		<p class="psymod-library-lock__text">
			<?php echo esc_html(sprintf(__('Этот материал доступен на уровне: %s.', 'psymod-library'), $access_label)); ?>
		</p>
		<div class="psymod-library-lock__actions">
			<a class="psymod-library-lock__btn psymod-library-lock__btn--primary" href="<?php echo esc_url($get_access); ?>">
				<?php echo esc_html__('Получить доступ', 'psymod-library'); ?>
			</a>
			<a class="psymod-library-lock__btn psymod-library-lock__btn--secondary" href="<?php echo esc_url($compare_url); ?>">
				<?php echo esc_html__('Сравнить уровни доступа', 'psymod-library'); ?>
			</a>
		</div>
	</div>
	<p class="psymod-single-material__back-wrap">
		<a class="psymod-single-material__back" href="<?php echo esc_url($library_url); ?>"><?php echo esc_html__('← Назад в библиотеку', 'psymod-library'); ?></a>
	</p>
	<?php echo $navigation_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
	</div>
	</div>
	<?php
	return (string) ob_get_clean();
}

/**
 * Render related materials block for single material page.
 */
function psymod_library_render_related_materials(int $post_id): string
{
	$related_ids = psymod_library_sanitize_related_materials(get_post_meta($post_id, 'related_materials', true));
	if (empty($related_ids)) {
		return '';
	}

	$related_ids = array_values(array_filter($related_ids, static function ($id) use ($post_id) {
		return (int) $id !== $post_id;
	}));
	if (empty($related_ids)) {
		return '';
	}

	$posts = get_posts(
		array(
			'post_type'      => PSYMOD_LIBRARY_POST_TYPE,
			'post_status'    => 'publish',
			'post__in'       => $related_ids,
			'orderby'        => 'post__in',
			'posts_per_page' => count($related_ids),
		)
	);

	if (empty($posts)) {
		return '';
	}

	ob_start();
	?>
	<section class="psymod-related-materials">
		<h2 class="psymod-related-materials__title"><?php echo esc_html__('Связанные материалы', 'psymod-library'); ?></h2>
		<div class="psymod-library-grid">
			<?php foreach ($posts as $related_post) : ?>
				<?php echo psymod_library_render_material_card((int) $related_post->ID); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php endforeach; ?>
		</div>
	</section>
	<?php

	return (string) ob_get_clean();
}

/**
 * Enqueue frontend styles.
 */
function psymod_library_enqueue_styles(): void
{
	$css = '.psymod-library-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:24px;align-items:stretch}'
		. '@media (max-width:1024px){.psymod-library-grid{grid-template-columns:repeat(2,minmax(0,1fr));}}'
		. '@media (max-width:640px){.psymod-library-grid{grid-template-columns:1fr;}}'
		. '.psymod-library-grid .psymod-material-card{display:flex;flex-direction:column;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 8px 28px rgba(15,23,42,.08);transition:transform .25s ease,box-shadow .25s ease;height:100%}'
		. '.psymod-library-grid .psymod-material-card:hover{transform:translateY(-6px);box-shadow:0 18px 36px rgba(15,23,42,.14)}'
		. '.psymod-library-grid .psymod-material-card__thumb{aspect-ratio:16/10;overflow:hidden;background:#e5e7eb}'
		. '.psymod-library-grid .psymod-material-card__thumb img{display:block;width:100%!important;height:100%!important;max-width:none!important;object-fit:cover!important;transition:transform .35s ease}'
		. '.psymod-library-grid .psymod-material-card:hover .psymod-material-card__thumb img{transform:scale(1.03)}'
		. '.psymod-material-card__content{padding:20px;display:flex;flex-direction:column;gap:12px;flex:1}'
		. '.psymod-material-card__title{margin:0;font-size:22px;line-height:1.25}'
		. '.psymod-material-card__title a{text-decoration:none;color:#1f2937}'
		. '.psymod-material-card__description{margin:0;color:#4b5563;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}'
		. '.psymod-material-card__meta{display:flex;align-items:center;min-height:20px}'
		. '.psymod-material-card__reading-time{font-size:13px;color:#9ca3af;line-height:1}'
		. '.psymod-material-card__badges{display:flex;flex-wrap:wrap;gap:8px;align-items:center}'
		. '.psymod-badge{display:inline-flex;align-items:center;justify-content:center;min-height:28px;padding:0 11px;border-radius:999px;font-size:12px;font-weight:600;line-height:1;white-space:nowrap;border:1px solid transparent}'
		. '.psymod-badge--public{background:#e0f2fe;color:#0c4a6e;border-color:#bae6fd}'
		. '.psymod-badge--free_user{background:#EEF6FF;color:#2563EB;border-color:#bfdbfe}'
		. '.psymod-badge--core{background:#ede9fe;color:#4c1d95;border-color:#d8b4fe}'
		. '.psymod-badge--pro{background:#ffe4e6;color:#9f1239;border-color:#fecdd3}'
		. '.psymod-badge--admin_only{background:#111827;color:#FFFFFF;border-color:#111827}'
		. '.psymod-badge--type{background:#f3f4f6;color:#374151;border-color:#e5e7eb}'
		. '.psymod-badge--free{background:#dcfce7;color:#166534;border-color:#bbf7d0}'
		. '.psymod-material-card__cta-wrap{margin-top:auto;padding-top:8px}'
		. '.psymod-material-card__cta{display:flex;justify-content:center;align-items:center;width:100%;min-height:48px;padding:11px 14px;border-radius:12px;background:#111827;color:#fff;text-decoration:none!important;font-weight:600;font-size:15px;letter-spacing:.01em;transition:transform .22s ease,background-color .22s ease,box-shadow .22s ease}'
		. '.psymod-material-card__cta:hover{background:#0b1220;transform:translateY(-2px);box-shadow:0 10px 20px rgba(17,24,39,.24)}'
		. '.psymod-material-card__cta:focus-visible{outline:2px solid #93c5fd;outline-offset:2px}'
		. '@media (max-width:640px){.psymod-library-grid .psymod-material-card{height:100%}.psymod-material-card__content{min-height:100%}}'
		. '.psymod-single-material-container{max-width:960px;margin:0 auto;padding:40px 20px}'
		. '.psymod-single-material{max-width:100%;margin:0 auto}'
		. '.psymod-single-material__hero{max-width:760px;margin:0 auto 36px auto;border-radius:22px;overflow:hidden}'
		. '.psymod-single-material__hero img{display:block;width:100%;height:420px;object-fit:cover;border-radius:22px;box-shadow:0 26px 60px rgba(15,23,42,.16)}'
		. '.psymod-single-material__meta{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 16px}'
		. '.psymod-single-material__reading-time{font-size:13px;color:#6b7280}'
		. '.psymod-single-material__content{background:#fff;border:1px solid #e5e7eb;border-radius:18px;padding:26px 28px;line-height:1.7;color:#1f2937}'
		. '.psymod-single-material__content h1,.psymod-single-material__content h2,.psymod-single-material__content h3{line-height:1.25;margin:0 0 14px;color:#111827}'
		. '.psymod-single-material__content p{margin:0 0 14px;line-height:1.75}'
		. '.psymod-related-materials{margin:34px 0 0}'
		. '.psymod-related-materials__title{margin:0 0 16px;font-size:28px;line-height:1.2;color:#111827}'
		. '.psymod-related-materials .psymod-library-grid{gap:24px}'
		. '.psymod-single-material__back-wrap{text-align:center;margin:32px auto}'
		. '.psymod-single-material__back{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:14px 22px;border-radius:14px;border:1px solid rgba(15,23,42,.08);background:#fff;color:#1f2937;text-decoration:none;transition:transform .24s ease,box-shadow .24s ease,border-color .24s ease}'
		. '.psymod-single-material__back:hover{transform:translateY(-2px);box-shadow:0 16px 32px rgba(15,23,42,.10);border-color:rgba(15,23,42,.18)}'
		. '.psymod-single-nav{max-width:960px;margin:48px auto 0;border-radius:24px;background:#fff;border:1px solid #e9edf3;padding:28px}'
		. '.psymod-single-nav__grid{display:grid;grid-template-columns:1fr 1px 1fr;gap:0;align-items:stretch}'
		. '.psymod-single-nav__divider{width:1px;background:linear-gradient(180deg,rgba(15,23,42,.04),rgba(15,23,42,.14),rgba(15,23,42,.04));margin:2px 10px}'
		. '.psymod-single-nav__item{display:flex;align-items:center;gap:14px;padding:18px 16px;border-radius:18px;text-decoration:none;color:#0f172a;transition:transform .25s ease,box-shadow .25s ease,background-color .25s ease}'
		. '.psymod-single-nav__item:hover{transform:translateY(-3px);background:#fbfcfe;box-shadow:0 16px 32px rgba(15,23,42,.10)}'
		. '.psymod-single-nav__item.is-empty{pointer-events:none}'
		. '.psymod-single-nav__item--next{justify-content:flex-end;text-align:right}'
		. '.psymod-single-nav__icon{display:inline-flex;align-items:center;justify-content:center;width:42px;height:42px;border-radius:999px;background:#f8eef2;color:#c06179;font-size:24px;line-height:1;flex:0 0 42px}'
		. '.psymod-single-nav__text{display:flex;flex-direction:column;gap:4px;min-width:0}'
		. '.psymod-single-nav__label{font-size:12px;line-height:1;letter-spacing:.12em;font-weight:700;color:#6b7280}'
		. '.psymod-single-nav__title{font-size:34px;line-height:1.2;font-weight:700;color:#111827;word-break:break-word}'
		. 'body.single-psymod_material .post-navigation:not(.psymod-single-nav),body.single-psymod_material .navigation.post-navigation,body.single-psymod_material .nav-links:not(.psymod-single-nav__links){display:none!important}'
		. '.psymod-library-lock{border:1px solid #e5e7eb;border-radius:14px;padding:22px;background:#f8fafc;max-width:760px}'
		. '.psymod-library-lock--single{max-width:760px;margin:28px auto 0;padding:28px 24px;text-align:center}'
		. '.psymod-library-lock__title{margin:0 0 8px;font-size:24px;line-height:1.25;color:#111827}'
		. '.psymod-library-lock__text{margin:0 0 16px;color:#374151}'
		. '.psymod-library-lock__actions{display:flex;flex-wrap:wrap;gap:10px;justify-content:center}'
		. '.psymod-library-lock__btn{display:inline-block;padding:10px 14px;border-radius:10px;text-decoration:none;font-weight:600}'
		. '.psymod-library-lock__btn--primary{background:#1f2937;color:#fff}'
		. '.psymod-library-lock__btn--secondary{background:#fff;color:#1f2937;border:1px solid #d1d5db}'
		. '.psymod-library-archive{max-width:1200px;margin:0 auto;padding:10px 0 24px}'
		. '.psymod-library-breadcrumbs{display:flex;gap:8px;align-items:center;font-size:14px;color:#6b7280;margin:0 0 14px}'
		. '.psymod-library-breadcrumbs a{text-decoration:none;color:#374151}'
		. '.psymod-library-hero{background:linear-gradient(135deg,#f8fafc,#eef2ff);border:1px solid #e5e7eb;border-radius:18px;padding:20px 22px;margin:0 0 20px}'
		. '.psymod-library-hero__title{margin:0 0 8px;font-size:34px;line-height:1.15;color:#111827}'
		. '.psymod-library-hero__description{margin:0;color:#4b5563;font-size:16px}'
		. '.psymod-library-hero__cta-wrap{margin:14px 0 0}'
		. '.psymod-library-hero__cta{display:inline-flex;align-items:center;justify-content:center;min-height:42px;padding:0 14px;border:1px solid #111827;border-radius:12px;background:#111827;color:#fff;text-decoration:none;font-weight:600}'
		. '.psymod-library-hero__cta:hover{background:#0b1220;color:#fff;text-decoration:none}'
		. '.psymod-library-tabs{display:flex;gap:10px;overflow-x:auto;padding:2px 0 8px;margin:0 0 14px;-webkit-overflow-scrolling:touch}'
		. '.psymod-library-tab{display:inline-flex;align-items:center;justify-content:center;padding:10px 14px;border-radius:999px;white-space:nowrap;text-decoration:none;background:#f3f4f6;border:1px solid #e5e7eb;color:#374151;font-weight:600;font-size:14px;transition:all .2s ease}'
		. '.psymod-library-tab:hover{background:#e5e7eb;color:#111827;text-decoration:none}'
		. '.psymod-library-tab.is-active{background:#111827;color:#fff;border-color:#111827;box-shadow:0 8px 16px rgba(17,24,39,.18)}'
		. '.psymod-library-search{display:block!important;visibility:visible!important;opacity:1!important;margin:0 0 12px}'
		. '.psymod-library-search__row{display:flex;gap:10px;align-items:stretch}'
		. '.psymod-library-search__input{flex:1;min-height:46px;border:1px solid #d1d5db;border-radius:12px;padding:0 14px;font-size:15px;background:#fff;color:#111827}'
		. '.psymod-library-search__button{min-height:46px;padding:0 18px;border:1px solid #111827;border-radius:12px;background:#111827;color:#fff;font-weight:600;cursor:pointer;transition:background-color .2s ease,transform .2s ease}'
		. '.psymod-library-search__button:hover{background:#0b1220;transform:translateY(-1px)}'
		. '.psymod-library-search__summary{display:flex;justify-content:space-between;gap:12px;align-items:center;margin:0 0 14px;color:#4b5563;font-size:14px}'
		. '.psymod-library-search__summary a{text-decoration:none;color:#2563eb;font-weight:600}'
		. '.psymod-category-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin:0 0 8px}'
		. '.psymod-category-grid__card{display:block;padding:16px 16px 14px;border:1px solid #e5e7eb;border-radius:16px;background:#fff;text-decoration:none;color:#111827;transition:transform .22s ease,box-shadow .22s ease,border-color .22s ease}'
		. '.psymod-category-grid__card:hover{transform:translateY(-2px);box-shadow:0 12px 24px rgba(15,23,42,.08);border-color:#cbd5e1;text-decoration:none;color:#0f172a}'
		. '.psymod-category-grid__name{font-size:18px;line-height:1.3;font-weight:700;margin:0 0 8px}'
		. '.psymod-category-grid__meta{display:flex;align-items:center;gap:8px;margin:0 0 6px}'
		. '.psymod-category-grid__count{display:inline-flex;align-items:center;justify-content:center;min-width:28px;height:28px;padding:0 8px;border-radius:999px;background:#e2e8f0;color:#1f2937;font-size:12px;font-weight:700}'
		. '.psymod-category-grid__desc{margin:0;font-size:13px;line-height:1.45;color:#64748b}'
		. '.psymod-category-breadcrumbs{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 10px;font-size:13px;color:#6b7280}'
		. '.psymod-category-breadcrumbs a{text-decoration:none;color:#4b5563}'
		. '.psymod-category-back-wrap{margin:0 0 24px}'
		. '.psymod-category-back{display:inline-flex;align-items:center;justify-content:center;padding:10px 14px;border-radius:12px;border:1px solid rgba(15,23,42,.08);background:#fff;color:#1f2937;text-decoration:none;transition:transform .2s ease,box-shadow .2s ease,border-color .2s ease}'
		. '.psymod-category-back:hover{transform:translateY(-1px);box-shadow:0 10px 20px rgba(15,23,42,.08);border-color:rgba(15,23,42,.18)}'
		. '.psymod-library-empty-state{max-width:780px;margin:8px auto 0;padding:28px 24px;border:1px solid #e5e7eb;border-radius:16px;background:#f8fafc;text-align:center}'
		. '.psymod-library-empty-state__title{margin:0 0 8px;font-size:24px;line-height:1.25;color:#111827}'
		. '.psymod-library-empty-state__text{margin:0;color:#6b7280}'
		. '.psymod-library-empty-state__actions{margin:16px 0 0}'
		. '.psymod-library-empty-state__link{text-decoration:none;font-weight:600;color:#2563eb}'
		. '.psymod-library-archive__grid{margin-top:14px}'
		. '@media (max-width:640px){.psymod-library-hero__title{font-size:28px}.psymod-library-tabs{margin:0 -4px 12px;padding:2px 4px 8px}.psymod-library-search__row{flex-direction:column}.psymod-library-search__button{width:100%}.psymod-library-search__summary{flex-direction:column;align-items:flex-start}.psymod-category-grid{grid-template-columns:1fr}.psymod-category-breadcrumbs{font-size:12px}.psymod-category-back{width:100%}.psymod-single-material-container{padding:28px 14px}.psymod-single-material__hero{max-width:100%;margin:0 auto 24px auto}.psymod-single-material__hero img{height:260px}.psymod-single-material__content{padding:18px 16px}.psymod-related-materials{margin-top:26px}.psymod-related-materials__title{font-size:24px}.psymod-single-material__back{width:100%}.psymod-single-nav{margin-top:34px;padding:18px}.psymod-single-nav__grid{grid-template-columns:1fr;gap:10px}.psymod-single-nav__divider{width:100%;height:1px;margin:2px 0;background:linear-gradient(90deg,rgba(15,23,42,.04),rgba(15,23,42,.16),rgba(15,23,42,.04))}.psymod-single-nav__item--next{justify-content:flex-start;text-align:left}.psymod-single-nav__title{font-size:28px}}';

	wp_register_style('psymod-library', false, array(), '1.0.1');
	wp_enqueue_style('psymod-library');
	wp_add_inline_style('psymod-library', $css);
}

/**
 * Shortcode [psymod_library].
 */
function psymod_library_shortcode(array $atts = array()): string
{
	$atts = shortcode_atts(
		array(
			'posts_per_page' => 12,
			'type'           => '',
			'free'           => '',
			'access'         => '',
			'search'         => '',
			'category'       => '',
			'empty_text'     => '',
		),
		$atts,
		'psymod_library'
	);

	$type_filter   = sanitize_title((string) $atts['type']);
	$free_filter   = (string) $atts['free'];
	$access_filter = psymod_library_sanitize_access_level($atts['access']);
	$search_filter = sanitize_text_field((string) $atts['search']);
	$category_filter = sanitize_title((string) $atts['category']);
	$empty_text      = sanitize_text_field((string) $atts['empty_text']);

	$has_access_filter = trim((string) $atts['access']) !== '';

	$query_args = array(
		'post_type'      => PSYMOD_LIBRARY_POST_TYPE,
		'post_status'    => 'publish',
		'posts_per_page' => (int) $atts['posts_per_page'],
		'orderby'        => array(
			'date'           => 'DESC',
		),
	);

	if ($search_filter !== '') {
		$query_args['psymod_library_search_ext'] = $search_filter;
	}

	$tax_query = array();
	if ($type_filter !== '') {
		$tax_query[] = array(
			'taxonomy' => 'material_type',
			'field'    => 'slug',
			'terms'    => array($type_filter),
		);
	}

	if ($category_filter !== '') {
		$tax_query[] = array(
			'taxonomy'         => 'material_category',
			'field'            => 'slug',
			'terms'            => array($category_filter),
			'include_children' => true,
		);
	}

	if (! empty($tax_query)) {
		if (count($tax_query) > 1) {
			$tax_query['relation'] = 'AND';
		}
		$query_args['tax_query'] = $tax_query;
	}

	$meta_query = array('relation' => 'AND');

	if ($free_filter === '1') {
		$meta_query[] = array(
			'key'     => 'is_in_free_collection',
			'value'   => '1',
			'compare' => '=',
		);
	}

	if ($has_access_filter) {
		$meta_query[] = array(
			'key'     => 'required_access_level',
			'value'   => $access_filter,
			'compare' => '=',
		);
	}

	if (count($meta_query) > 1) {
		$query_args['meta_query'] = $meta_query;
	}

	$query = new WP_Query($query_args);

	ob_start();
	?>
	<div class="psymod-library-grid">
		<?php if ($query->have_posts()) : ?>
			<?php
			$posts = $query->posts;
			usort(
				$posts,
				static function (WP_Post $a, WP_Post $b): int {
					$order_a = (int) get_post_meta($a->ID, 'material_order', true);
					$order_b = (int) get_post_meta($b->ID, 'material_order', true);

					if ($order_a !== $order_b) {
						return $order_a <=> $order_b;
					}

					return strtotime((string) $b->post_date_gmt) <=> strtotime((string) $a->post_date_gmt);
				}
			);

			foreach ($posts as $material_post) {
				echo psymod_library_render_material_card((int) $material_post->ID);
			}
			?>
		<?php else : ?>
			<?php echo psymod_library_render_empty_state($search_filter, $empty_text); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		<?php endif; ?>
	</div>
	<?php

	wp_reset_postdata();
	return (string) ob_get_clean();
}
