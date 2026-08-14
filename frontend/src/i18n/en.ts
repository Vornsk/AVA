// English catalog. Record<keyof typeof ko, string> enforces full key parity at compile time.
import { ko } from './ko'

export const en: Record<keyof typeof ko, string> = {
  // Sidebar groups
  'group.workspace': 'Workspace',
  'group.diagnosis': 'Assessment',
  'group.results': 'Results',
  'group.intelligence': 'Intelligence',
  'group.admin': 'Admin',

  // Sidebar items
  'nav.overview': 'Overview',
  'nav.projects': 'Projects',
  'nav.recon': 'Recon',
  'nav.scan': 'Scan',
  'nav.findings': 'Findings',
  'nav.coverage': 'Coverage',
  'nav.report': 'Report',
  'nav.reverify': 'Reverify',
  'nav.advisor': 'Rule Advisor',
  'nav.audit': 'Audit',
  'nav.users': 'Users',
  'sidebar.readonly': 'Read-only',

  // Page headers (App META)
  'page.overview.title': 'Project Workspace',
  'page.overview.subtitle': 'Target scope and status summary',
  'page.projects.title': 'Projects',
  'page.projects.subtitle': 'Create, switch, and manage project access',
  'page.recon.title': 'Recon',
  'page.recon.subtitle': 'Endpoints, request verdicts, scope, and auth status',
  'page.scan.title': 'Automated Assessment',
  'page.scan.subtitle': 'Run assessment — detectors, guardrails, payloads',
  'page.findings.title': 'Findings',
  'page.findings.subtitle': 'Manage discovered vulnerabilities and review status',
  'page.coverage.title': 'Check Coverage',
  'page.coverage.subtitle': 'Assessment results vs. checklist — pass, vulnerable, unchecked',
  'page.report.title': 'Findings Export',
  'page.report.subtitle': 'Export to the standard Excel format (11 columns)',
  'page.reverify.title': 'Reverification',
  'page.reverify.subtitle': 'Recheck remediation and compare changes across scans',
  'page.advisor.title': 'Rule Advisor',
  'page.advisor.subtitle': 'LLM decision log and rule recommendations',
  'page.audit.title': 'Audit Log',
  'page.audit.subtitle': 'All change history — who, when, and what',
  'page.users.title': 'User Management',
  'page.users.subtitle': 'Account list and creation — leader only',

  // Topbar
  'topbar.logout': 'Log out',
  'topbar.themeToggle': 'Toggle theme',
  'topbar.langToggle': 'Switch language',

  // Login
  'login.user': 'Username',
  'login.password': 'Password',
  'login.errInvalid': 'Invalid username or password.',
  'login.errServer': 'Cannot connect to the server.',
  'login.submit': 'Sign in',
  'login.submitting': 'Signing in…',
  'login.demoHint': 'Demo accounts — leader / leader123 · analyst / analyst123 ',
  'login.demoNote': '(be sure to change before production)',

  // Overview
  'overview.allSchemes': 'All schemes',
  'overview.noScans': 'No scans have run yet.',
}
