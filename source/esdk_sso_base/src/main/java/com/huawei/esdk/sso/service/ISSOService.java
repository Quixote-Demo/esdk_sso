package com.huawei.esdk.sso.service;

import com.huawei.esdk.sso.SSOAuthProcessor;
import com.huawei.esdk.sso.SSOResult;

public interface ISSOService
{
    void registerSSOAuthProcessor(SSOAuthProcessor processor);
    
    String ssoAuth(String message);
    
    String buildResMsgBody(String code, SSOResult result);
}
