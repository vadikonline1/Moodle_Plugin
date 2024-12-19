<?php
defined('MOODLE_INTERNAL') || die();

function local_disable_ldap_users_sync_execute_for_all_users() {
    global $DB;

    $users = $DB->get_records('user', array('deleted' => 0)); 

    foreach ($users as $user) {
        $status = check_ad_status($user->username, $user);
        log_user_modification($user, $status);
    }
}

function check_ad_status($username, $user) {

    if ($user->suspended == 1) {
        $status = $user->username . ' - Contul deja suspendat în Moodle. Trecem la următorul utilizator.';
        log_user_modification($user, $status);
        mtrace($status);
        return $status;
    }

    $ldap_host = get_config('auth_ldap', 'host_url');
    $ldap_dn = get_config('auth_ldap', 'contexts');
    $ldap_user = get_config('auth_ldap', 'bind_dn');
    $ldap_password = get_config('auth_ldap', 'bind_pw');

    $ldap_conn = ldap_connect($ldap_host);
    if (!$ldap_conn) {
        return 'Eroare de conectare la serverul LDAP: ' . ldap_error($ldap_conn);
    }

    ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldap_conn, LDAP_OPT_REFERRALS, 0);

    $bind = ldap_bind($ldap_conn, $ldap_user, $ldap_password);
    if (!$bind) {
        ldap_close($ldap_conn);
        return 'Eroare de autentificare în LDAP: ' . ldap_error($ldap_conn);
    }

    $filter = "(sAMAccountName=$username)";
    $search = ldap_search($ldap_conn, $ldap_dn, $filter);

    if (!$search) {
        ldap_close($ldap_conn);
        return 'Eroare la efectuarea căutării în LDAP: ' . ldap_error($ldap_conn);
    }

    $entries = ldap_get_entries($ldap_conn, $search);

    if ($entries['count'] > 0) {
        $account_disabled = $entries[0]['useraccountcontrol'][0];
        if ($account_disabled & 2) {
            suspend_user_in_moodle($user);
            ldap_close($ldap_conn);
            $status = $user->username . ' - Contul din Active Directory este dezactivat. Utilizatorul a fost suspendat în Moodle.';
            mtrace($status);
            return $status;
        } else {
            ldap_close($ldap_conn);
            $status = $user->username . ' - Contul din Active Directory este activ.';
            mtrace($status);
            return $status;
        }
    } else {
        suspend_user_in_moodle($user);
        ldap_close($ldap_conn);
        $status = $user->username . ' - Utilizatorul nu a fost găsit în Active Directory.';
        mtrace($status);
        return $status;
    }
}

function log_user_modification($user, $status) {
    $logfile = get_config('local_disable_ldap_users_sync', 'logfile');
    if (empty($logfile)) {
        $logfile = __DIR__ . '/user_modifications.log';
    }

    $log = fopen($logfile, 'a');

    if ($log) {
        $log_message = date('Y-m-d H:i:s') . ' - User: ' . $status . "\n";

        fwrite($log, $log_message);
        fclose($log);
    } else {
        mtrace("Eroare la deschiderea fișierului de loguri.");
    }
}
