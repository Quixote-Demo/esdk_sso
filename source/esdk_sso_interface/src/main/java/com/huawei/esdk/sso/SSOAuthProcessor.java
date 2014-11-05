package com.huawei.esdk.sso;

import java.util.Map;

public interface SSOAuthProcessor
{
    SDKResult<SSOResult> doAuthenticate(Map<String, Object> parameters);
}
