<?php
function local_mfa_user_check_extend_navigation_user($user) {
    global $DB, $USER, $PAGE;

    $plugin_enabled = get_config('local_mfa_user_check', 'enabled');

    if (!$plugin_enabled) {
        return;
    }
	// Verificăm dacă utilizatorul este în lista albă
    $whitelist_ids = get_config('local_mfa_user_check', 'whitelist_users_id');
    // Dacă nu există setare pentru whitelist, atribuim un ID implicit (ID-ul 2)
    if (empty($whitelist_ids)) {
        $whitelist_ids = '2'; // ID-ul implicit
    }
    $whitelist_ids = explode(',', $whitelist_ids); // Împărțim ID-urile utilizatorilor

    if (in_array($USER->id, $whitelist_ids)) {
        return;
    }

    if (isloggedin() && !isguestuser()) {
        $redirect_url = '/admin/tool/mfa/user_preferences.php';
        $current_url = $PAGE->url->out();
		$exclude_urls = [
			$redirect_url,
			'/admin/tool/mfa/'
			];


		foreach ($exclude_urls as $url) {
			if (strpos($current_url, $url) !== false) {
				return;
			}
		}

        $result = $DB->get_records('tool_mfa', array('userid' => $USER->id, 'factor' => 'totp', 'revoked' => 0));
        if ($result) {
			return;
        }
		redirect(new moodle_url($redirect_url));
    }
}
