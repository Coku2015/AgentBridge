import { ApiRequestError } from './api'
import { t } from './i18n'

interface Diagnostic {
  status?: string
  error?: string
  reason?: string
  detail?: string
  failureStage?: string
}

function diagnostic(source: unknown): Diagnostic {
  if (source instanceof ApiRequestError) {
    return {
      status: source.resultStatus,
      error: source.code,
      detail: source.detail,
      failureStage: source.failureStage,
    }
  }
  if (source instanceof Error) return { detail: source.message }
  if (source && typeof source === 'object') return source as Diagnostic
  if (typeof source === 'string') return { detail: source }
  return {}
}

function diagnosticText(source: unknown): string {
  const value = diagnostic(source)
  return [value.error, value.status, value.failureStage, value.detail]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
}

function timestamp(now: Date): string {
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`
}

function failureLine(host: string, reason: string, now: Date, port?: number): string {
  const target = port ? `${host} : ${port}` : host
  return `${timestamp(now)} ${target} ${reason}`.replace(/\s+/g, ' ').trim()
}

function isNetworkFailure(text: string): boolean {
  return /network_timeout|network_unreachable|connection_refused|smb_unavailable|i\/o timeout|deadline exceeded|no route to host|network is unreachable|connection refused|host is down/.test(text)
}

function isNameResolutionFailure(text: string): boolean {
  return /host_not_found|no such host|name resolution|server misbehaving/.test(text)
}

function isAuthenticationFailure(text: string): boolean {
  return /authentication_failed|windows_authentication_failed|kerberos_realm_missing|unable to authenticate|no supported methods|logon failure|username or password|用户名或密码/.test(text)
}

function networkTarget(host: string, port: number): string {
  const value = host.trim()
  const formattedHost = value.includes(':') && !value.startsWith('[') ? `[${value}]` : value
  return `${formattedHost}:${port}`
}

// VBR discovery spans DNS, TCP, TLS, OAuth, and two REST compatibility probes.
// Present those failures as operator actions rather than leaking Go/network API
// error chains. Text matching remains as a compatibility fallback for older
// AgentBridge servers that returned only a raw detail string.
export function formatVBRConnectionError(source: unknown, host: string, port: number): string {
  const text = diagnosticText(source)
  const target = networkTarget(host, port)

  if (/vbr_host_not_found|no such host|host not found|name resolution|server misbehaving/.test(text)) {
    return t('errorpresentation.vbr.host.could.not.be.resolved', target)
  }
  if (/vbr_connection_timeout|i\/o timeout|deadline exceeded|client\.timeout exceeded|timeout awaiting response headers/.test(text)) {
    return t('errorpresentation.vbr.connection.timed.out', target, port)
  }
  if (/vbr_connection_refused|connection refused/.test(text)) {
    return t('errorpresentation.vbr.connection.was.refused', target, port)
  }
  if (/vbr_network_unreachable|no route to host|network is unreachable|host is down|network unreachable/.test(text)) {
    return t('errorpresentation.vbr.network.is.unreachable', target)
  }
  if (/vbr_tls_fingerprint_changed|fingerprint (?:does not match|mismatch)/.test(text)) {
    return t('errorpresentation.vbr.tls.certificate.changed', target)
  }
  if (/vbr_tls_handshake_failed|server presented no certificate|tls handshake|first record does not look like a tls handshake|server gave http response to https client|remote error: tls|protocol version|x509:|connection reset by peer|unexpected eof/.test(text)) {
    return t('errorpresentation.vbr.tls.connection.failed', target, port)
  }
  if (/vbr_authentication_failed|invalid_grant|invalid credentials|authentication failed|username or password|oauth2 token grant returned (?:400|401)/.test(text)) {
    return t('errorpresentation.vbr.authentication.failed')
  }
  if (/vbr_access_forbidden|oauth2 token grant returned 403|403 forbidden|access denied/.test(text)) {
    return t('errorpresentation.vbr.access.was.denied')
  }
  if (/vbr_api_not_found|oauth2 token grant returned 404|404 not found/.test(text)) {
    return t('errorpresentation.vbr.rest.api.was.not.found', target, port)
  }
  if (/vbr_service_unavailable|oauth2 token grant returned (?:429|500|502|503|504)|service unavailable|too many requests/.test(text)) {
    return t('errorpresentation.vbr.rest.api.is.unavailable', target)
  }
  if (/vbr_response_invalid|decode token|empty access token|invalid character|unexpected end of json input/.test(text)) {
    return t('errorpresentation.vbr.response.was.invalid', target)
  }
  if (/vbr_server_info_unavailable|server info failed/.test(text)) {
    return t('errorpresentation.vbr.server.information.is.unavailable')
  }
  if (/vbr_capability_probe_failed|capability probe failed/.test(text)) {
    return t('errorpresentation.vbr.capability.probe.failed')
  }
  return t('errorpresentation.vbr.connection.failed', target, port)
}

function installerOutput(source: unknown): string {
  const detail = diagnostic(source).detail || ''
  const marker = '; output: '
  const index = detail.indexOf(marker)
  return index >= 0 ? detail.slice(index + marker.length).trim() : ''
}

export function formatAgentPackageDownloadError(source: unknown): string {
  const value = diagnostic(source)
  if (value.error === 'agent_package_archive_invalid') {
    return t('errorpresentation.vbr.returned.an.invalid.agent.package.archive')
  }
  if (source instanceof Error && source.message) return source.message
  return value.detail || t('errorpresentation.agent.package.download.failed')
}

export function formatLinuxRemoteError(
  source: unknown,
  host: string,
  port: number,
  auth: '' | 'password' | 'key',
  operation: 'probe' | 'install' = 'probe',
  now = new Date(),
): string {
  const text = diagnosticText(source)
  let reason: string

  if (isNameResolutionFailure(text)) {
    reason = t('errorpresentation.the.host.name.could.not.be.resolved')
  } else if (isNetworkFailure(text)) {
    reason = t('errorpresentation.connection.failed.the.target.is.unreachable')
  } else if (/host_key_changed|host key changed|host key mismatch|pin mismatch/.test(text)) {
    reason = t('errorpresentation.the.target.host.identity.changed.the.connection')
  } else if (/private_key_invalid|private key invalid|private key passphrase/.test(text)) {
    reason = t('errorpresentation.the.private.key.or.its.passphrase.is')
  } else if (/credential_missing|no auth method|credentials? (?:is|are) required/.test(text)) {
    reason = t('errorpresentation.login.credentials.are.missing')
  } else if (isAuthenticationFailure(text)) {
    reason = auth === 'key'
      ? t('errorpresentation.the.username.or.private.key.is.incorrect')
      : t('errorpresentation.the.username.or.password.is.incorrect')
  } else if (/ssh_handshake_failed|ssh handshake|host key not observed|connection reset by peer/.test(text)) {
    reason = t('errorpresentation.the.target.is.reachable.but.an.ssh')
  } else if (/privilege_required/.test(text)) {
    reason = t('errorpresentation.the.account.is.not.root.and.privilege')
  } else if (/sudo_password_required/.test(text)) {
    reason = t('errorpresentation.sudo.requires.the.current.account.password')
  } else if (/sudo_password_invalid/.test(text)) {
    reason = t('errorpresentation.the.sudo.password.is.incorrect')
  } else if (/sudo_not_authorized/.test(text)) {
    reason = t('errorpresentation.the.current.account.is.not.authorized.to')
  } else if (/sudo_unavailable/.test(text)) {
    reason = t('errorpresentation.sudo.is.not.installed.on.the.target')
  } else if (/root_password_required/.test(text)) {
    reason = t('errorpresentation.the.selected.elevation.option.requires.the.root')
  } else if (/root_password_invalid/.test(text)) {
    reason = t('errorpresentation.the.root.password.is.incorrect')
  } else if (/su_unavailable/.test(text)) {
    reason = t('errorpresentation.su.is.unavailable.on.the.target')
  } else if (/sudoers_validator_missing/.test(text)) {
    reason = t('errorpresentation.visudo.is.missing.the.sudoers.update.was')
  } else if (/sudoers_directory_missing/.test(text)) {
    reason = t('errorpresentation.the.target.does.not.provide.a.sudoers')
  } else if (/sudoers_account_missing/.test(text)) {
    reason = t('errorpresentation.the.current.account.could.not.be.resolved')
  } else if (/sudoers_update_failed/.test(text)) {
    reason = t('errorpresentation.the.sudoers.configuration.could.not.be.validated')
  } else if (/privilege_identity_failed|privilege_escalation_failed/.test(text)) {
    reason = t('errorpresentation.the.account.privilege.could.not.be.verified')
  } else if (/remote_permission_denied|permission denied/.test(text)) {
    reason = operation === 'probe'
      ? t('errorpresentation.login.succeeded.but.permission.to.probe.the')
      : t('errorpresentation.login.succeeded.but.installation.permission.was.denied')
  } else if (/probe_response_invalid|probe_response_unsupported|probe.*(?:decode|schema)/.test(text)) {
    reason = t('errorpresentation.login.succeeded.but.the.system.probe.result')
  } else if (operation === 'install' && /no compatible agent payload/.test(text)) {
    reason = t('errorpresentation.no.agent.package.is.compatible.with.this')
  } else if (operation === 'install' && /prepare failed/.test(text)) {
    reason = t('errorpresentation.installation.preparation.failed')
  } else if (operation === 'install' && /deployment_kit_verification_failed/.test(text)) {
    reason = t('errorpresentation.the.installer.ran.but.the.deployment.kit')
  } else if (operation === 'install' && /agent_package_verification_failed/.test(text)) {
    reason = t('errorpresentation.the.agent.installer.ran.but.the.installed')
  } else if (operation === 'install' && /verify failed/.test(text)) {
    reason = t('errorpresentation.installation.ran.but.result.verification.failed')
  } else if (operation === 'install') {
    reason = t('errorpresentation.component.installation.failed')
  } else {
    reason = t('errorpresentation.system.probe.failed')
  }

  const line = failureLine(host, reason, now, port)
  const output = operation === 'install' ? installerOutput(source) : ''
  return output ? `${line}; output: ${output}` : line
}

export function formatWindowsRemoteError(source: unknown, host: string, now = new Date()): string {
  const text = diagnosticText(source)
  let reason: string

  if (isNameResolutionFailure(text)) {
    reason = t('errorpresentation.the.host.name.could.not.be.resolved.2')
  } else if (isNetworkFailure(text)) {
    reason = t('errorpresentation.connection.failed.the.target.is.unreachable.2')
  } else if (/windows_account_locked/.test(text)) {
    reason = t('errorpresentation.the.account.is.locked')
  } else if (/windows_password_expired/.test(text)) {
    reason = t('errorpresentation.the.password.has.expired')
  } else if (/windows_password_change_required/.test(text)) {
    reason = t('errorpresentation.the.password.must.be.changed.on.the')
  } else if (/windows_account_disabled/.test(text)) {
    reason = t('errorpresentation.the.account.is.disabled')
  } else if (/windows_remote_logon_denied/.test(text)) {
    reason = t('errorpresentation.the.account.is.not.allowed.to.sign')
  } else if (isAuthenticationFailure(text)) {
    reason = t('errorpresentation.the.username.or.password.is.incorrect.2')
  } else if (/windows_request_invalid|request_validation/.test(text)) {
    reason = t('errorpresentation.the.host.username.or.password.is.incomplete')
  } else if (/remote_privilege_restricted|task_scheduler_access_denied|remote_authorization/.test(text)) {
    reason = t('errorpresentation.login.succeeded.but.remote.administrator.permission.was')
  } else if (/admin_share_unavailable|rpc_security_context_missing|task_scheduler_rpc_unavailable|task_scheduler_service_(?:not_running|unavailable)|rpc_(?:authentication|connection)/.test(text)) {
    reason = t('errorpresentation.the.target.is.reachable.but.remote.administration')
  } else if (/task_scheduler_service_busy/.test(text)) {
    reason = t('errorpresentation.remote.administration.is.busy.try.again.later')
  } else if (/task_definition_invalid|task_(?:account|definition)|task_xml_|sched_e_/.test(text)) {
    reason = t('errorpresentation.the.remote.installation.task.is.not.compatible')
  } else if (/deployment_kit_(?:campaign_invalid|missing|read_failed|integrity_failed)/.test(text)) {
    reason = t('errorpresentation.the.deployment.kit.is.expired.missing.or')
  } else if (/remote_staging_failed|deployment_kit_upload_failed|installer_script_upload_failed|smb_upload/.test(text)) {
    reason = t('errorpresentation.installation.file.transfer.failed')
  } else if (/windows_install_timeout|installer_wait/.test(text)) {
    reason = t('errorpresentation.remote.installation.timed.out')
  } else if (/veeam_deployment_service_/.test(text)) {
    reason = t('errorpresentation.installation.completed.but.the.veeam.deployment.service')
  } else if (/deployment_kit_installer_|installer_result_invalid| install_failed| installer /.test(` ${text} `)) {
    reason = t('errorpresentation.deployment.kit.installation.failed')
  } else {
    reason = t('errorpresentation.the.windows.remote.operation.failed')
  }

  return failureLine(host, reason, now)
}

export function formatDeploymentKitProbeError(source: unknown, host: string, now = new Date()): string {
  const value = diagnostic(source)
  const text = `${value.reason || ''} ${value.error || ''} ${value.detail || ''}`.toLowerCase()
  let reason: string
  if (/host_unresolved|no such host|name resolution/.test(text)) {
    reason = t('errorpresentation.the.host.name.could.not.be.resolved.3')
  } else if (/network_unreachable|timeout|no route|network is unreachable/.test(text)) {
    reason = t('errorpresentation.connection.failed.the.target.is.unreachable.3')
  } else if (/deployment_kit_campaign_invalid/.test(text)) {
    reason = t('errorpresentation.the.deployment.kit.changed.generate.a.new')
  } else if (/request_invalid/.test(text)) {
    reason = t('errorpresentation.the.readiness.probe.request.is.invalid')
  } else {
    reason = t('errorpresentation.the.deployment.kit.service.is.unavailable')
  }
  return failureLine(host, reason, now)
}
