# Installation of the local_ipaddress Plugin

Note: Moodle configuration file `base_dir/moodle/config.php`
```php 
if (!empty($_SERVER['HTTP_X_FORWARDER_FOR'])) {$_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDER_FOR'];} 
```

To install the local_ipaddress plugin, follow these steps:
1. Copy the plugin code into the local folder of the main Moodle directory.
2. Run the Moodle upgrade script:
   ```php
   php admin/cli/upgrade.php
   ```
   or
   With an admin account, access the platform, which will display an installation page. Follow the steps shown in the browser.
3. After installing the plugin, you need to add the following lines of PHP code to the config.php file in the main Moodle directory:

```php
if (file_exists($CFG->dirroot . '/local/ipaddress/router.php')) {
  require_once $CFG->dirroot . '/local/ipaddress/router.php';
}
```

These lines should be added at the end of the config.php file.

# Configuration of the local_ipaddress Plugin

To configure the plugin, access the settings page with an admin account: `Site Administration => Plugins => Local plugins => IP Address Restrictions`

On this page, you will define what IPs represent "internal IPs" or "intranet" at the platform level. Add one IP per line in the "IP Whitelist (intranet)" field.

Additionally, on this page, you can enter the text that should be displayed to users when they access a page where they do not have access with their current IP.

To set which category and course restricts user access based on the IP address, a new field "IP address restriction" has been added in the category and course add/edit page. This field can have one of the following options:
- **Internal IPs** – The category/course can only be accessed from the IPs listed as "internal IPs" or "intranet."
- **External IPs** – The category/course is not restricted by IP address.

# Testing the local_ipaddress Plugin

IP address-based access restrictions apply only to users who do not have Moodle admin roles. For testing, we need both a Moodle admin account and a regular user account.

To test the plugin, a category and course structure should be built.
With the Moodle admin account, go to: `Site Administration => Courses => Manage courses and categories`

Create a category and course structure like this:

Category 1  
  Category 2  
    Category 3  
      Course 1  

Enroll the regular user in Course 1, and then test multiple scenarios:

1. Structure with the following IP restriction settings:  
   Category 1 – External IPs  
   Category 2 – External IPs  
   Category 3 – External IPs  
     Course 1 – External IPs

   Course 1, as well as the categories, are accessible by the user regardless of their IP.

2. Structure with the following IP restriction settings:  
   Category 1 – External IPs  
   Category 2 – External IPs  
   Category 3 – External IPs  
     Course 1 – Internal IPs

   Course 1 is accessible only from internal IPs, but the categories are accessible by the user regardless of their IP.

3. Structure with the following IP restriction settings:  
   Category 1 – External IPs  
   Category 2 – External IPs  
   Category 3 – Internal IPs  
     Course 1 – External IPs

   Course 1 and Category 3 are accessible only from internal IPs, but other categories are accessible by the user regardless of their IP. Note that if a category is restricted to internal IPs, this restriction will apply to all subcategories and courses inside this category. In this case, Course 1 is restricted because it is inside Category 3, even though there is no direct restriction on the course.

4. Structure with the following IP restriction settings:  
   Category 1 – External IPs  
   Category 2 – Internal IPs  
   Category 3 – External IPs  
     Course 1 – External IPs

   Course 1, Category 2, and Category 3 are accessible only from internal IPs, but Category 1 is accessible by the user regardless of their IP.

5. Structure with the following IP restriction settings:  
   Category 1 – Internal IPs  
   Category 2 – External IPs  
   Category 3 – External IPs  
     Course 1 – External IPs

   Course 1, Category 1, Category 2, and Category 3 are accessible only from internal IPs.
