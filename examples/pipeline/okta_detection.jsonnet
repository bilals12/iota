local iota = import '../../pkg/config/iota.libsonnet';

{
  transforms: [
    // Admin role assignment
    iota.tf.detect(
      id='OKTA_ADMIN_ROLE_ASSIGNED',
      title='Okta Admin Role Assigned',
      condition=iota.cnd.str.equals('eventType', 'user.account.privilege.grant'),
      severity='HIGH',
      tags=['okta', 'admin', 'privilege'],
      dedup_key='actor.alternateId',
    ),

    // API token creation
    iota.tf.detect(
      id='OKTA_API_TOKEN_CREATED',
      title='Okta API Token Created',
      condition=iota.cnd.str.equals('eventType', 'system.api_token.create'),
      severity='HIGH',
      tags=['okta', 'api', 'credential'],
    ),

    // MFA reset
    iota.tf.detect(
      id='OKTA_MFA_RESET',
      title='Okta MFA Factor Reset',
      condition=iota.cnd.any([
        iota.cnd.str.equals('eventType', 'user.mfa.factor.deactivate'),
        iota.cnd.str.equals('eventType', 'user.mfa.factor.reset_all'),
      ]),
      severity='MEDIUM',
      tags=['okta', 'mfa'],
    ),

    // Suspicious login patterns
    iota.tf.detect(
      id='OKTA_LOGIN_FAILURE',
      title='Okta Login Failure',
      condition=iota.cnd.all([
        iota.cnd.str.equals('eventType', 'user.session.start'),
        iota.cnd.str.equals('outcome.result', 'FAILURE'),
      ]),
      severity='LOW',
      tags=['okta', 'auth', 'failure'],
      dedup_key='client.ipAddress',
      threshold=5,
    ),

    // Support access
    iota.tf.detect(
      id='OKTA_SUPPORT_ACCESS',
      title='Okta Support Access to Tenant',
      condition=iota.cnd.str.equals('eventType', 'user.session.impersonation.grant'),
      severity='CRITICAL',
      tags=['okta', 'support', 'access'],
    ),

    // Route all alerts to stdout
    iota.tf.alert([iota.tf.send.stdout()]),
  ],
}
