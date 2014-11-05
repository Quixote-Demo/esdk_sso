package com.huawei.esdk.sso.service;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

import com.google.gson.Gson;
import com.huawei.esdk.platform.common.utils.MaskUtils;
import com.huawei.esdk.platform.common.utils.StringUtils;
import com.huawei.esdk.sso.SDKResult;
import com.huawei.esdk.sso.SSOResult;
import com.huawei.esdk.sso.bean.DelegateAuthReqBean;
import com.huawei.esdk.sso.bean.DelegateAuthResBean;

public class SSORestDelegateService extends AbstractService implements ISSOService
{
    private static final Logger LOGGER = Logger.getLogger(SSORestDelegateService.class);
    
    private static SSORestDelegateService instance = new SSORestDelegateService();
    
    private SSORestDelegateService()
    {
    }
    
    public static SSORestDelegateService getInstance()
    {
        return instance;
    }
    
    public String ssoAuth(String message)
    {
        Map<String, Object> inputFileds = null;
        String maskedMessage = MaskUtils.maskJson(message, "pwd");
        try
        {
            inputFileds = buildParameter(message);
        }
        catch(Exception e)
        {
            LOGGER.warn("The input paramters are not correct, please check:" + maskedMessage);
            LOGGER.error("", e);
            return buildResMsgBody("-1", new SSOResult());
        }
        if (!isValidInput(inputFileds))
        {
            LOGGER.warn("The input paramters are not correct, please check:" + maskedMessage);
            return buildResMsgBody("-1", new SSOResult());
        }
        
        SDKResult<SSOResult> sdkResult = processor.doAuthenticate(inputFileds);
        
        String ssoErrorCode = sdkResult.getResultCode();
        if (!"0".equals(ssoErrorCode))
        {
            LOGGER.warn("Fail to auth through SSO Server, the error code is :" + ssoErrorCode);
            LOGGER.warn("The message is:" + "\n\r" + maskedMessage);
        }
        
        return buildResMsgBody(ssoErrorCode, null == sdkResult.getResult() ? new SSOResult() : sdkResult.getResult());
    }
    
    private boolean isValidInput(Map<String, Object> param)
    {
        if (null == param)
        {
            return false;
        }
        if (StringUtils.isEmpty((String)param.get("clientIPAddresss"))
            || StringUtils.isEmpty((String)param.get("authType")))
        {
            return false;
        }
        
        return true;
    }
    
    private Map<String, Object> buildParameter(String message)
    {
        Gson gson = new Gson();
        DelegateAuthReqBean req = gson.fromJson(message, DelegateAuthReqBean.class);
        Map<String, Object> map = new HashMap<String, Object>();
        if (null != req)
        {
            map.put("enterpriseID", req.getEnterpriseID());
            map.put("clientIPAddresss", req.getClientIPAddresss());
            map.put("authType", req.getAuthType());
            map.put("credential", req.getCredential());
            map.put("account", req.getAccount());
            map.put("pwd", req.getPwd());
            map.put("remark1", req.getRemark1());
            map.put("remark2", req.getRemark2());
        }
        return map;
    }
    
    @Override
    public String buildResMsgBody(String code, SSOResult result)
    {
        DelegateAuthResBean res = new DelegateAuthResBean();
        res.setResCode(getEsdkErrorCode(code));
        res.setCredential(StringUtils.avoidNull(result.getCredential()));
        res.setUID(StringUtils.avoidNull(result.getUid()));
        res.setRemark1(StringUtils.avoidNull(result.getRemark1()));
        res.setRemark2(StringUtils.avoidNull(result.getRemark2()));
        
        Gson gson = new Gson();
        return gson.toJson(res);
    }
}
