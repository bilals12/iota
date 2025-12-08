{
  // Conditions
  cnd: {
    // Meta conditions (combinators)
    all(conditions): {
      type: 'meta_all',
      settings: { conditions: conditions },
    },
    any(conditions): {
      type: 'meta_any',
      settings: { conditions: conditions },
    },
    none(conditions): {
      type: 'meta_none',
      settings: { conditions: conditions },
    },

    // String conditions
    str: {
      contains(key, value): {
        type: 'string_contains',
        settings: { object: { source_key: key }, value: value },
      },
      equals(key, value): {
        type: 'string_equals',
        settings: { object: { source_key: key }, value: value },
      },
      starts_with(key, value): {
        type: 'string_starts_with',
        settings: { object: { source_key: key }, value: value },
      },
      ends_with(key, value): {
        type: 'string_ends_with',
        settings: { object: { source_key: key }, value: value },
      },
      match(key, pattern): {
        type: 'string_match',
        settings: { object: { source_key: key }, value: pattern },
      },
    },

    // Number conditions
    num: {
      equals(key, value): {
        type: 'number_equals',
        settings: { object: { source_key: key }, value: value },
      },
      gt(key, value): {
        type: 'number_greater_than',
        settings: { object: { source_key: key }, value: value },
      },
      lt(key, value): {
        type: 'number_less_than',
        settings: { object: { source_key: key }, value: value },
      },
    },

    // Utility conditions
    exists(key): {
      type: 'exists',
      settings: { object: { source_key: key } },
    },
    format_json(): {
      type: 'format_json',
      settings: {},
    },
  },

  // Transforms
  tf: {
    // Object transforms
    obj: {
      copy(src, trg): {
        type: 'object_copy',
        settings: { object: { source_key: src, target_key: trg } },
      },
      delete(key): {
        type: 'object_delete',
        settings: { object: { source_key: key } },
      },
      insert(key, value): {
        type: 'object_insert',
        settings: { object: { target_key: key }, value: value },
      },
    },

    // String transforms
    str: {
      to_lower(key, trg=null): {
        type: 'string_to_lower',
        settings: { object: { source_key: key, target_key: if trg != null then trg else key } },
      },
      to_upper(key, trg=null): {
        type: 'string_to_upper',
        settings: { object: { source_key: key, target_key: if trg != null then trg else key } },
      },
      replace(key, pattern, replacement, trg=null): {
        type: 'string_replace',
        settings: {
          object: { source_key: key, target_key: if trg != null then trg else key },
          pattern: pattern,
          replacement: replacement,
        },
      },
    },

    // Meta transforms
    meta: {
      switch(cases): {
        type: 'meta_switch',
        settings: { cases: cases },
      },
      for_each(key, transforms): {
        type: 'meta_for_each',
        settings: { object: { source_key: key }, transforms: transforms },
      },
    },

    // Enrichment transforms
    enrich: {
      dns_reverse(key, trg=null): {
        type: 'enrich_dns_reverse',
        settings: { object: { source_key: key, target_key: trg } },
      },
      dns_forward(key, trg=null): {
        type: 'enrich_dns_forward',
        settings: { object: { source_key: key, target_key: trg } },
      },
      http_get(url, key=null, trg='enrichment', headers={}): {
        type: 'enrich_http_get',
        settings: {
          url: url,
          object: { source_key: key, target_key: trg },
          headers: headers,
        },
      },
      geoip(key, trg=null): {
        type: 'enrich_geoip',
        settings: { object: { source_key: key, target_key: trg } },
      },
    },

    // Detection transforms
    detect(id, title, condition, severity='INFO', description='', tags=[], dedup_key='', threshold=1): {
      type: 'detect',
      settings: {
        id: id,
        title: title,
        description: description,
        severity: severity,
        tags: tags,
        condition: condition,
        dedup_key: dedup_key,
        threshold: threshold,
      },
    },

    alert(outputs): {
      type: 'alert',
      settings: { outputs: outputs },
    },

    // Send transforms
    send: {
      stdout(): {
        type: 'send_stdout',
        settings: {},
      },
      slack(webhook_url, channel=null, username=null): {
        type: 'send_slack',
        settings: {
          webhook_url: webhook_url,
          [if channel != null then 'channel']: channel,
          [if username != null then 'username']: username,
        },
      },
      http_post(url, headers={}): {
        type: 'send_http_post',
        settings: { url: url, headers: headers },
      },
    },

    // Utility transforms
    util: {
      drop(): {
        type: 'utility_drop',
        settings: {},
      },
      control(): {
        type: 'utility_control',
        settings: {},
      },
    },
  },

  // Detection rule helper
  rule(id, title, condition, severity='INFO', description='', tags=[], outputs=[]):
    [
      $.tf.detect(id, title, condition, severity, description, tags),
      $.tf.alert(if std.length(outputs) > 0 then outputs else [$.tf.send.stdout()]),
    ],

  // Conditional transform pattern
  when(condition, transforms):
    $.tf.meta.switch([{ condition: condition, transforms: transforms }]),
}
