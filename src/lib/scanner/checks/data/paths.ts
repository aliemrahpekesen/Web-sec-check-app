// Curated sensitive-path catalog. Each entry becomes an individually-tracked
// disclosure check. `tier` bounds when it's probed (1 = STANDARD+, 2 = DEEP).
// `sig` (optional) is an extra content signature so a check only fires on a
// *real* file, not a soft-404 / SPA catch-all — this is what keeps disclosure
// findings accurate.
import type { Severity } from "../types";
import { SENSITIVE_PATHS_EXTENDED } from "./paths-extended";
import { SENSITIVE_PATHS_EXTENDED_2 } from "./paths-extended-2";

export interface PathSig {
  path: string;
  tier: 1 | 2;
  severity: Severity;
  title: string;
  sig?: RegExp;
  group: string;
}

const BASE_PATHS: PathSig[] = [
  // --- VCS metadata ---------------------------------------------------------
  { path: "/.git/config", tier: 1, severity: "CRITICAL", title: ".git/config", sig: /\[core\]|\[remote/i, group: "vcs" },
  { path: "/.git/HEAD", tier: 1, severity: "CRITICAL", title: ".git/HEAD", sig: /ref:\s*refs\//i, group: "vcs" },
  { path: "/.git/index", tier: 2, severity: "CRITICAL", title: ".git/index", group: "vcs" },
  { path: "/.git/logs/HEAD", tier: 2, severity: "CRITICAL", title: ".git/logs/HEAD", group: "vcs" },
  { path: "/.gitignore", tier: 2, severity: "LOW", title: ".gitignore", group: "vcs" },
  { path: "/.svn/entries", tier: 1, severity: "HIGH", title: ".svn/entries", group: "vcs" },
  { path: "/.svn/wc.db", tier: 2, severity: "HIGH", title: ".svn/wc.db", group: "vcs" },
  { path: "/.hg/store/00manifest.i", tier: 2, severity: "HIGH", title: "Mercurial store", group: "vcs" },
  { path: "/.bzr/branch/branch.conf", tier: 2, severity: "HIGH", title: "Bazaar branch", group: "vcs" },
  { path: "/CVS/Root", tier: 2, severity: "MEDIUM", title: "CVS/Root", group: "vcs" },

  // --- Environment / secrets ------------------------------------------------
  { path: "/.env", tier: 1, severity: "CRITICAL", title: ".env", sig: /^[A-Z0-9_]+\s*=/m, group: "secrets" },
  { path: "/.env.local", tier: 1, severity: "CRITICAL", title: ".env.local", group: "secrets" },
  { path: "/.env.production", tier: 1, severity: "CRITICAL", title: ".env.production", group: "secrets" },
  { path: "/.env.development", tier: 2, severity: "HIGH", title: ".env.development", group: "secrets" },
  { path: "/.env.backup", tier: 2, severity: "CRITICAL", title: ".env.backup", group: "secrets" },
  { path: "/.env.bak", tier: 2, severity: "CRITICAL", title: ".env.bak", group: "secrets" },
  { path: "/.env.save", tier: 2, severity: "CRITICAL", title: ".env.save", group: "secrets" },
  { path: "/config/.env", tier: 2, severity: "CRITICAL", title: "config/.env", group: "secrets" },
  { path: "/.aws/credentials", tier: 1, severity: "CRITICAL", title: "AWS credentials", sig: /aws_access_key_id/i, group: "secrets" },
  { path: "/.aws/config", tier: 2, severity: "HIGH", title: "AWS config", group: "secrets" },
  { path: "/.npmrc", tier: 2, severity: "HIGH", title: ".npmrc (token)", sig: /_authToken|registry/i, group: "secrets" },
  { path: "/.netrc", tier: 2, severity: "HIGH", title: ".netrc", group: "secrets" },
  { path: "/.pgpass", tier: 2, severity: "HIGH", title: ".pgpass", group: "secrets" },
  { path: "/.dockercfg", tier: 2, severity: "HIGH", title: ".dockercfg", group: "secrets" },
  { path: "/.docker/config.json", tier: 2, severity: "HIGH", title: "docker config.json", group: "secrets" },
  { path: "/secrets.json", tier: 2, severity: "CRITICAL", title: "secrets.json", group: "secrets" },
  { path: "/credentials.json", tier: 2, severity: "CRITICAL", title: "credentials.json", group: "secrets" },
  { path: "/id_rsa", tier: 1, severity: "CRITICAL", title: "id_rsa private key", sig: /PRIVATE KEY/i, group: "secrets" },
  { path: "/id_dsa", tier: 2, severity: "CRITICAL", title: "id_dsa private key", group: "secrets" },
  { path: "/.ssh/id_rsa", tier: 2, severity: "CRITICAL", title: ".ssh/id_rsa", group: "secrets" },
  { path: "/server.key", tier: 2, severity: "CRITICAL", title: "server.key", sig: /PRIVATE KEY/i, group: "secrets" },
  { path: "/privatekey.pem", tier: 2, severity: "CRITICAL", title: "privatekey.pem", group: "secrets" },

  // --- Config files ---------------------------------------------------------
  { path: "/config.json", tier: 1, severity: "HIGH", title: "config.json", group: "config" },
  { path: "/config.yml", tier: 2, severity: "HIGH", title: "config.yml", group: "config" },
  { path: "/config.yaml", tier: 2, severity: "HIGH", title: "config.yaml", group: "config" },
  { path: "/config.php", tier: 2, severity: "MEDIUM", title: "config.php", group: "config" },
  { path: "/settings.py", tier: 2, severity: "HIGH", title: "settings.py", sig: /SECRET_KEY|DATABASES/i, group: "config" },
  { path: "/application.properties", tier: 2, severity: "HIGH", title: "application.properties", group: "config" },
  { path: "/application.yml", tier: 2, severity: "HIGH", title: "application.yml", group: "config" },
  { path: "/appsettings.json", tier: 1, severity: "HIGH", title: "appsettings.json", sig: /ConnectionStrings|Logging/i, group: "config" },
  { path: "/web.config", tier: 1, severity: "MEDIUM", title: "web.config", sig: /<configuration|<system\.web/i, group: "config" },
  { path: "/wp-config.php", tier: 1, severity: "HIGH", title: "wp-config.php", group: "config" },
  { path: "/wp-config.php.bak", tier: 1, severity: "CRITICAL", title: "wp-config.php.bak", sig: /DB_PASSWORD|DB_NAME/i, group: "config" },
  { path: "/wp-config.php.old", tier: 2, severity: "CRITICAL", title: "wp-config.php.old", group: "config" },
  { path: "/wp-config.php.save", tier: 2, severity: "CRITICAL", title: "wp-config.php.save", group: "config" },
  { path: "/configuration.php", tier: 2, severity: "HIGH", title: "Joomla configuration.php", group: "config" },
  { path: "/config/database.yml", tier: 1, severity: "CRITICAL", title: "Rails database.yml", sig: /adapter:|password:/i, group: "config" },
  { path: "/config/secrets.yml", tier: 2, severity: "CRITICAL", title: "Rails secrets.yml", group: "config" },
  { path: "/config/master.key", tier: 2, severity: "CRITICAL", title: "Rails master.key", group: "config" },
  { path: "/.terraform/terraform.tfstate", tier: 2, severity: "CRITICAL", title: "terraform.tfstate", group: "config" },
  { path: "/terraform.tfstate", tier: 1, severity: "CRITICAL", title: "terraform.tfstate", sig: /"terraform_version"/i, group: "config" },
  { path: "/docker-compose.yml", tier: 1, severity: "MEDIUM", title: "docker-compose.yml", sig: /services:|image:/i, group: "config" },
  { path: "/Dockerfile", tier: 2, severity: "LOW", title: "Dockerfile", sig: /^FROM /im, group: "config" },
  { path: "/.dockerignore", tier: 2, severity: "INFO", title: ".dockerignore", group: "config" },

  // --- Backups / archives ---------------------------------------------------
  { path: "/backup.zip", tier: 1, severity: "HIGH", title: "backup.zip", group: "backup" },
  { path: "/backup.tar.gz", tier: 1, severity: "HIGH", title: "backup.tar.gz", group: "backup" },
  { path: "/backup.sql", tier: 1, severity: "CRITICAL", title: "backup.sql", sig: /INSERT INTO|CREATE TABLE/i, group: "backup" },
  { path: "/db.sql", tier: 1, severity: "CRITICAL", title: "db.sql", group: "backup" },
  { path: "/database.sql", tier: 1, severity: "CRITICAL", title: "database.sql", group: "backup" },
  { path: "/dump.sql", tier: 1, severity: "CRITICAL", title: "dump.sql", group: "backup" },
  { path: "/backup.tar", tier: 2, severity: "HIGH", title: "backup.tar", group: "backup" },
  { path: "/backup.bak", tier: 2, severity: "HIGH", title: "backup.bak", group: "backup" },
  { path: "/www.zip", tier: 2, severity: "HIGH", title: "www.zip", group: "backup" },
  { path: "/site.zip", tier: 2, severity: "HIGH", title: "site.zip", group: "backup" },
  { path: "/backup.old", tier: 2, severity: "MEDIUM", title: "backup.old", group: "backup" },
  { path: "/index.php.bak", tier: 2, severity: "MEDIUM", title: "index.php.bak", group: "backup" },
  { path: "/index.html.bak", tier: 2, severity: "LOW", title: "index.html.bak", group: "backup" },
  { path: "/.index.php.swp", tier: 2, severity: "MEDIUM", title: "vim swap (.swp)", group: "backup" },
  { path: "/#index.php#", tier: 2, severity: "LOW", title: "emacs autosave", group: "backup" },

  // --- Debug / info endpoints -----------------------------------------------
  { path: "/phpinfo.php", tier: 1, severity: "HIGH", title: "phpinfo()", sig: /phpinfo\(\)|PHP Version/i, group: "debug" },
  { path: "/info.php", tier: 1, severity: "HIGH", title: "info.php (phpinfo)", sig: /PHP Version/i, group: "debug" },
  { path: "/test.php", tier: 2, severity: "MEDIUM", title: "test.php", group: "debug" },
  { path: "/server-status", tier: 1, severity: "MEDIUM", title: "Apache server-status", sig: /Apache Server Status|Server uptime/i, group: "debug" },
  { path: "/server-info", tier: 1, severity: "MEDIUM", title: "Apache server-info", sig: /Apache Server Information/i, group: "debug" },
  { path: "/status", tier: 2, severity: "LOW", title: "/status", group: "debug" },
  { path: "/debug", tier: 2, severity: "MEDIUM", title: "/debug", group: "debug" },
  { path: "/actuator", tier: 1, severity: "HIGH", title: "Spring Boot actuator", sig: /"_links"|"health"/i, group: "debug" },
  { path: "/actuator/health", tier: 1, severity: "LOW", title: "actuator/health", sig: /"status"/i, group: "debug" },
  { path: "/actuator/env", tier: 1, severity: "CRITICAL", title: "actuator/env", sig: /"propertySources"|"activeProfiles"/i, group: "debug" },
  { path: "/actuator/heapdump", tier: 2, severity: "CRITICAL", title: "actuator/heapdump", group: "debug" },
  { path: "/actuator/mappings", tier: 2, severity: "MEDIUM", title: "actuator/mappings", group: "debug" },
  { path: "/actuator/configprops", tier: 2, severity: "HIGH", title: "actuator/configprops", group: "debug" },
  { path: "/_profiler", tier: 2, severity: "HIGH", title: "Symfony profiler", group: "debug" },
  { path: "/telescope", tier: 2, severity: "HIGH", title: "Laravel Telescope", group: "debug" },
  { path: "/_debugbar", tier: 2, severity: "MEDIUM", title: "Laravel Debugbar", group: "debug" },
  { path: "/__debug__/", tier: 2, severity: "MEDIUM", title: "Django debug toolbar", group: "debug" },
  { path: "/rails/info/properties", tier: 2, severity: "MEDIUM", title: "Rails info", group: "debug" },
  { path: "/metrics", tier: 2, severity: "MEDIUM", title: "Prometheus /metrics", sig: /# HELP|# TYPE/i, group: "debug" },

  // --- Admin / auth panels --------------------------------------------------
  { path: "/admin", tier: 1, severity: "INFO", title: "/admin panel", group: "admin" },
  { path: "/administrator/", tier: 2, severity: "INFO", title: "/administrator (Joomla)", group: "admin" },
  { path: "/wp-admin/", tier: 1, severity: "INFO", title: "/wp-admin", group: "admin" },
  { path: "/wp-login.php", tier: 1, severity: "INFO", title: "/wp-login.php", sig: /user_login|wordpress/i, group: "admin" },
  { path: "/admin/login", tier: 2, severity: "INFO", title: "/admin/login", group: "admin" },
  { path: "/phpmyadmin/", tier: 1, severity: "MEDIUM", title: "phpMyAdmin", sig: /phpMyAdmin/i, group: "admin" },
  { path: "/pma/", tier: 2, severity: "MEDIUM", title: "phpMyAdmin (pma)", group: "admin" },
  { path: "/adminer.php", tier: 2, severity: "MEDIUM", title: "Adminer", sig: /Adminer/i, group: "admin" },
  { path: "/manager/html", tier: 2, severity: "HIGH", title: "Tomcat Manager", group: "admin" },
  { path: "/console", tier: 2, severity: "MEDIUM", title: "/console", group: "admin" },
  { path: "/.well-known/security.txt", tier: 2, severity: "INFO", title: "security.txt (iyi uygulama)", group: "admin" },

  // --- API docs / schema ----------------------------------------------------
  { path: "/swagger-ui.html", tier: 1, severity: "LOW", title: "Swagger UI", sig: /swagger/i, group: "api" },
  { path: "/swagger/index.html", tier: 2, severity: "LOW", title: "Swagger UI", group: "api" },
  { path: "/swagger.json", tier: 1, severity: "LOW", title: "swagger.json", sig: /"swagger"|"openapi"/i, group: "api" },
  { path: "/openapi.json", tier: 1, severity: "LOW", title: "openapi.json", sig: /"openapi"/i, group: "api" },
  { path: "/api-docs", tier: 2, severity: "LOW", title: "/api-docs", group: "api" },
  { path: "/v2/api-docs", tier: 2, severity: "LOW", title: "Springfox api-docs", group: "api" },
  { path: "/graphql", tier: 1, severity: "MEDIUM", title: "GraphQL endpoint", group: "api" },
  { path: "/graphiql", tier: 2, severity: "MEDIUM", title: "GraphiQL IDE", sig: /graphiql/i, group: "api" },
  { path: "/.well-known/apple-app-site-association", tier: 2, severity: "INFO", title: "apple-app-site-association", group: "api" },

  // --- Logs -----------------------------------------------------------------
  { path: "/error.log", tier: 1, severity: "MEDIUM", title: "error.log", group: "logs" },
  { path: "/errors.log", tier: 2, severity: "MEDIUM", title: "errors.log", group: "logs" },
  { path: "/debug.log", tier: 1, severity: "MEDIUM", title: "debug.log", group: "logs" },
  { path: "/access.log", tier: 1, severity: "MEDIUM", title: "access.log", group: "logs" },
  { path: "/laravel.log", tier: 2, severity: "MEDIUM", title: "Laravel log", group: "logs" },
  { path: "/storage/logs/laravel.log", tier: 1, severity: "MEDIUM", title: "storage/logs/laravel.log", sig: /\[\d{4}-\d{2}-\d{2}/i, group: "logs" },
  { path: "/logs/", tier: 2, severity: "LOW", title: "/logs directory", group: "logs" },
  { path: "/npm-debug.log", tier: 2, severity: "LOW", title: "npm-debug.log", group: "logs" },

  // --- Source maps / build artefacts ---------------------------------------
  { path: "/main.js.map", tier: 2, severity: "LOW", title: "main.js.map (kaynak haritası)", sig: /"sources"|"mappings"/i, group: "sourcemap" },
  { path: "/app.js.map", tier: 2, severity: "LOW", title: "app.js.map", group: "sourcemap" },
  { path: "/bundle.js.map", tier: 2, severity: "LOW", title: "bundle.js.map", group: "sourcemap" },
  { path: "/package.json", tier: 1, severity: "LOW", title: "package.json", sig: /"dependencies"|"name"/i, group: "sourcemap" },
  { path: "/package-lock.json", tier: 2, severity: "LOW", title: "package-lock.json", group: "sourcemap" },
  { path: "/composer.json", tier: 1, severity: "LOW", title: "composer.json", sig: /"require"/i, group: "sourcemap" },
  { path: "/composer.lock", tier: 2, severity: "LOW", title: "composer.lock", group: "sourcemap" },
  { path: "/yarn.lock", tier: 2, severity: "INFO", title: "yarn.lock", group: "sourcemap" },
  { path: "/Gemfile", tier: 2, severity: "LOW", title: "Gemfile", sig: /gem ['"]/i, group: "sourcemap" },
  { path: "/Gemfile.lock", tier: 2, severity: "LOW", title: "Gemfile.lock", group: "sourcemap" },
  { path: "/requirements.txt", tier: 2, severity: "INFO", title: "requirements.txt", group: "sourcemap" },
  { path: "/webpack.config.js", tier: 2, severity: "LOW", title: "webpack.config.js", group: "sourcemap" },

  // --- OS / editor cruft ----------------------------------------------------
  { path: "/.DS_Store", tier: 1, severity: "LOW", title: ".DS_Store", sig: /Bud1|\x00\x00\x00\x01Bud1/i, group: "cruft" },
  { path: "/Thumbs.db", tier: 2, severity: "INFO", title: "Thumbs.db", group: "cruft" },
  { path: "/.htaccess", tier: 1, severity: "MEDIUM", title: ".htaccess", sig: /RewriteRule|Options |Order /i, group: "cruft" },
  { path: "/.htpasswd", tier: 1, severity: "HIGH", title: ".htpasswd", sig: /:\$apr1\$|:\$2y\$/i, group: "cruft" },
  { path: "/.user.ini", tier: 2, severity: "MEDIUM", title: ".user.ini", group: "cruft" },
  { path: "/crossdomain.xml", tier: 1, severity: "LOW", title: "crossdomain.xml", sig: /cross-domain-policy/i, group: "cruft" },
  { path: "/clientaccesspolicy.xml", tier: 2, severity: "LOW", title: "clientaccesspolicy.xml", group: "cruft" },

  // --- CI / project metadata ------------------------------------------------
  { path: "/.gitlab-ci.yml", tier: 2, severity: "MEDIUM", title: ".gitlab-ci.yml", sig: /stages:|script:/i, group: "ci" },
  { path: "/.travis.yml", tier: 2, severity: "LOW", title: ".travis.yml", group: "ci" },
  { path: "/.circleci/config.yml", tier: 2, severity: "LOW", title: "CircleCI config", group: "ci" },
  { path: "/Jenkinsfile", tier: 2, severity: "LOW", title: "Jenkinsfile", group: "ci" },
  { path: "/.github/workflows/", tier: 2, severity: "INFO", title: ".github/workflows", group: "ci" },
  { path: "/.editorconfig", tier: 2, severity: "INFO", title: ".editorconfig", group: "ci" },
  { path: "/.vscode/settings.json", tier: 2, severity: "INFO", title: ".vscode/settings.json", group: "ci" },
  { path: "/.idea/workspace.xml", tier: 2, severity: "LOW", title: ".idea/workspace.xml", group: "ci" },

  // --- Misc high-value ------------------------------------------------------
  { path: "/robots.txt", tier: 1, severity: "INFO", title: "robots.txt (bilgi)", sig: /User-agent|Disallow/i, group: "misc" },
  { path: "/sitemap.xml", tier: 2, severity: "INFO", title: "sitemap.xml", group: "misc" },
  { path: "/.well-known/openid-configuration", tier: 2, severity: "INFO", title: "OpenID configuration", group: "misc" },
  { path: "/elmah.axd", tier: 2, severity: "HIGH", title: "ELMAH error log", sig: /Error Log for/i, group: "misc" },
  { path: "/trace.axd", tier: 2, severity: "HIGH", title: "ASP.NET trace.axd", sig: /Application Trace/i, group: "misc" },
  { path: "/.vs/", tier: 2, severity: "LOW", title: "Visual Studio .vs", group: "misc" },
  { path: "/readme.html", tier: 2, severity: "INFO", title: "readme.html (WP version)", sig: /WordPress/i, group: "misc" },
  { path: "/license.txt", tier: 2, severity: "INFO", title: "license.txt", group: "misc" },
  { path: "/CHANGELOG.md", tier: 2, severity: "INFO", title: "CHANGELOG.md", group: "misc" },
];

// De-duplicate by path (base list wins on any accidental collision).
const seenPaths = new Set(BASE_PATHS.map((p) => p.path));
export const SENSITIVE_PATHS: PathSig[] = [...BASE_PATHS];
for (const extra of [...SENSITIVE_PATHS_EXTENDED, ...SENSITIVE_PATHS_EXTENDED_2]) {
  if (!seenPaths.has(extra.path)) {
    seenPaths.add(extra.path);
    SENSITIVE_PATHS.push(extra);
  }
}
