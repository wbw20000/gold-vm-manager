"""Non-secret first-boot choices. Passwords are never accepted by this schema."""
LANGUAGES = ('en-US','en-GB','zh-Hans','zh-Hant','ja','de','fr')
COUNTRIES = ('US','GB','JP','SG','DE','CA','AU','FR','NL','HK')
TIMEZONES = ('America/Los_Angeles','America/New_York','America/Chicago','America/Toronto',
 'America/Vancouver','Europe/London','Europe/Berlin','Europe/Paris','Europe/Amsterdam',
 'Asia/Tokyo','Asia/Singapore','Asia/Hong_Kong','Australia/Sydney','Australia/Perth','Etc/UTC')
DEFAULT = {'version':1,'language':'en-US','country':'US','timezone':'America/Los_Angeles',
 'location_services':False,'skip_migration':True,'skip_apple_account':True,'share_analytics':False}


def validate(value=None):
    if value is None: return dict(DEFAULT)
    if type(value) is not dict or set(value) != set(DEFAULT):
        raise ValueError('初始化模板字段无效；此接口不接收账号或密码')
    if type(value['version']) is not int or value['version'] != 1:
        raise ValueError('初始化模板版本无效')
    for key, allowed in [('language',LANGUAGES),('country',COUNTRIES),('timezone',TIMEZONES)]:
        if type(value[key]) is not str or value[key] not in allowed:
            raise ValueError('语言、地区或时区不在当前支持的模板列表中')
    for key in ('location_services','skip_migration','skip_apple_account','share_analytics'):
        if type(value[key]) is not bool: raise ValueError('隐私设置必须为明确布尔值')
    if value['share_analytics'] or not value['skip_migration'] or not value['skip_apple_account']:
        raise ValueError('干净初始化暂不支持迁移资料、自动账号登录或共享分析数据')
    return dict(value)
