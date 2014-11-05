package com.huawei.esdk.sso.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.google.gson.Gson;
import com.huawei.esdk.platform.common.utils.StringUtils;
import com.huawei.esdk.sso.SDKResult;
import com.huawei.esdk.sso.SSOResult;
import com.huawei.esdk.sso.bean.ProdAcctPwdReqBean;
import com.huawei.esdk.sso.bean.ProdAcctPwdResBean;
import com.huawei.esdk.sso.bean.UserInfo;

public class SSORestProdService extends AbstractService implements ISSOService
{
    private static final Logger LOGGER = Logger.getLogger(SSORestProdService.class);
    
    private static SSORestProdService instance = new SSORestProdService();
    
    private SSORestProdService()
    {
    }
    
    public static SSORestProdService getInstance()
    {
        return instance;
    }
    
    @Override
    public String ssoAuth(String message)
    {
        Map<String, Object> inputFileds = null;
        try
        {
            inputFileds = buildParameter(message);
        }
        catch (Exception e)
        {
            LOGGER.warn("The input paramters are not correct, please check:" + message);
            LOGGER.error("", e);
            return buildResMsgBody("-1", new SSOResult());
        }
        if (!isValidInput(inputFileds))
        {
            LOGGER.warn("The input paramters are not correct, please check:" + message);
            return buildResMsgBody("-1", new SSOResult());
        }
        
        //通过后向企业SSO认证服务器发起令牌验证请求（ISV定制，见5.1.1)
        SDKResult<SSOResult> result = processor.doAuthenticate(inputFileds);
        
        if (!"0".equals(result.getResultCode()))
        {
            LOGGER.warn("Fail to auth through SSO Server, the error code is :" + result.getResultCode());
            LOGGER.warn("The incoming message is " + message);
            //如果认证不通过则直接返回eSDK-Client错误码
            return buildResMsgBody(result.getResultCode(), result.getResult());
        }
        else
        {
            //如果认证通过，则调用产品提供的接口获取用户名和密码
            //获取到用户名和密码后，封装Json格式返回eSDK
            return buildResMsgBody(result.getResultCode(),
                result.getResult(),
                getUserInfo((String)inputFileds.get("credential")));
        }
        
    }
    
    protected List<UserInfo> getUserInfo(String ticket)
    {
        List<UserInfo> users = new ArrayList<UserInfo>();
        //TODO Retrieve Product User name and Password
        UserInfo user = new UserInfo();
        user.setProduct("IVSSDK");
        user.setName("z0012345");
        user.setPassword("12345678");
        users.add(user);
        
        user = new UserInfo();
        user.setProduct("UCSDK");
        user.setName("z0012345");
        user.setPassword("12345678");
        users.add(user);
        return users;
    }
    
    @Override
    public String buildResMsgBody(String code, SSOResult result)
    {
        List<UserInfo> users = new ArrayList<UserInfo>();
        return buildResMsgBody(code, result, users);
    }
    
    private String buildResMsgBody(String code, SSOResult result, List<UserInfo> users)
    {
        ProdAcctPwdResBean resultBean = new ProdAcctPwdResBean();
        resultBean.setResCode(getEsdkErrorCode(code));
        resultBean.setUserinfo(users);
        Gson gson = new Gson();
        return gson.toJson(resultBean);
    }
    
    private Map<String, Object> buildParameter(String message)
    {
        Map<String, Object> result = new HashMap<String, Object>();
        Gson gson = new Gson();
        ProdAcctPwdReqBean req = gson.fromJson(message, ProdAcctPwdReqBean.class);
        if (null != req)
        {
            result.put("credential", req.getCredential());
            result.put("remark", req.getRemark());
        }
        return result;
    }
    
    private boolean isValidInput(Map<String, Object> parameters)
    {
        String credential = (String)parameters.get("credential");
        if (StringUtils.isEmpty(credential))
        {
            return false;
        }
        else
        {
            return true;
        }
    }
}
