local iota = import '../../pkg/config/iota.libsonnet';

{
  transforms: [
    // Root account usage detection
    iota.tf.detect(
      id='AWS_ROOT_ACTIVITY',
      title='Root Account Activity Detected',
      condition=iota.cnd.str.equals('userIdentity.type', 'Root'),
      severity='CRITICAL',
      description='Activity performed by the root AWS account',
      tags=['aws', 'iam', 'root'],
      dedup_key='userIdentity.arn',
    ),

    // IAM privilege escalation
    iota.tf.detect(
      id='AWS_IAM_PRIVESC',
      title='Potential IAM Privilege Escalation',
      condition=iota.cnd.any([
        iota.cnd.str.equals('eventName', 'CreatePolicyVersion'),
        iota.cnd.str.equals('eventName', 'SetDefaultPolicyVersion'),
        iota.cnd.str.equals('eventName', 'AttachUserPolicy'),
        iota.cnd.str.equals('eventName', 'AttachGroupPolicy'),
        iota.cnd.str.equals('eventName', 'AttachRolePolicy'),
        iota.cnd.str.equals('eventName', 'PutUserPolicy'),
        iota.cnd.str.equals('eventName', 'PutGroupPolicy'),
        iota.cnd.str.equals('eventName', 'PutRolePolicy'),
      ]),
      severity='HIGH',
      tags=['aws', 'iam', 'privesc'],
    ),

    // Console login without MFA
    iota.tf.detect(
      id='AWS_CONSOLE_LOGIN_NO_MFA',
      title='Console Login Without MFA',
      condition=iota.cnd.all([
        iota.cnd.str.equals('eventName', 'ConsoleLogin'),
        iota.cnd.str.equals('additionalEventData.MFAUsed', 'No'),
      ]),
      severity='HIGH',
      tags=['aws', 'iam', 'mfa'],
    ),

    // S3 bucket policy changes
    iota.tf.detect(
      id='AWS_S3_BUCKET_POLICY_CHANGE',
      title='S3 Bucket Policy Modified',
      condition=iota.cnd.any([
        iota.cnd.str.equals('eventName', 'PutBucketPolicy'),
        iota.cnd.str.equals('eventName', 'DeleteBucketPolicy'),
        iota.cnd.str.equals('eventName', 'PutBucketAcl'),
      ]),
      severity='MEDIUM',
      tags=['aws', 's3', 'policy'],
    ),

    // Security group changes
    iota.tf.detect(
      id='AWS_SG_CHANGE',
      title='Security Group Modified',
      condition=iota.cnd.any([
        iota.cnd.str.equals('eventName', 'AuthorizeSecurityGroupIngress'),
        iota.cnd.str.equals('eventName', 'AuthorizeSecurityGroupEgress'),
        iota.cnd.str.equals('eventName', 'RevokeSecurityGroupIngress'),
        iota.cnd.str.equals('eventName', 'RevokeSecurityGroupEgress'),
        iota.cnd.str.equals('eventName', 'CreateSecurityGroup'),
        iota.cnd.str.equals('eventName', 'DeleteSecurityGroup'),
      ]),
      severity='MEDIUM',
      tags=['aws', 'ec2', 'security-group'],
    ),

    // Route alerts based on severity
    iota.tf.meta.switch([
      {
        condition: iota.cnd.str.equals('meta alert.severity', 'CRITICAL'),
        transforms: [
          iota.tf.send.stdout(),
          // Add PagerDuty, Slack, etc. for critical alerts
        ],
      },
      {
        condition: iota.cnd.str.equals('meta alert.severity', 'HIGH'),
        transforms: [
          iota.tf.send.stdout(),
        ],
      },
      {
        // Default: just log to stdout
        transforms: [
          iota.tf.send.stdout(),
        ],
      },
    ]),
  ],
}
