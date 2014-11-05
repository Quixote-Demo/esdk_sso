package com.huawei.esdk.sso.service;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;

import com.huawei.esdk.platform.common.utils.MaskUtils;
import com.huawei.esdk.sso.SDKResult;
import com.huawei.esdk.sso.SSOResult;

public class SSOXMLService extends AbstractService implements ISSOService
{
    protected static final Logger LOGGER = Logger.getLogger(SSOXMLService.class);
    
    private static SSOXMLService instance = new SSOXMLService();
    
    private SSOXMLService()
    {
    }
    
    public static SSOXMLService getInstance()
    {
        return instance;
    }
    
    @Override
    public String ssoAuth(String message)
    {
        Map<String, Object> params = parseXML(message);
        SDKResult<SSOResult> sdkResult = processor.doAuthenticate(params);
        String ssoErrorCode = sdkResult.getResultCode();
        if (!"0".equals(ssoErrorCode))
        {
            LOGGER.warn("Fail to auth through SSO Server, the error code is :" + ssoErrorCode);
            LOGGER.warn("The message is:" + "\n\r" + MaskUtils.maskXMLElementValue(message, "pwd"));
        }
        String esdkCode = getEsdkErrorCode(ssoErrorCode);
        
        String xml = buildResMsgBody(esdkCode, null == sdkResult.getResult() ? new SSOResult() : sdkResult.getResult());
        return xml;
    }
    
    @Override
    public String buildResMsgBody(String code, SSOResult result)
    {
        String xml = "<root><resCode>";
        xml = xml + code + "</resCode>";
        xml = xml + "<UID>" + (null == result.getUid() ? "" : result.getUid()) + "</UID>";
        xml = xml + "<credential>" + (null == result.getCredential() ? "" : result.getCredential()) + "</credential>";
        xml = xml + "<remark1>" + (null == result.getRemark1() ? "" : result.getRemark1()) + "</remark1>";
        xml = xml + "<remark2>" + (null == result.getRemark2() ? "" : result.getRemark2()) + "</remark2>";
        xml = xml + "</root>";
        return xml;
    }
    
    private Map<String, Object> parseXML(String xml)
    {
        Map<String, Object> map = new HashMap<String, Object>();
        Document doc = null;
        try
        {
            doc = DocumentHelper.parseText(xml);// 将字符串转为XML
            Element root = doc.getRootElement(); // 获取根节点
            String enterpriseID = root.elementTextTrim("enterpriseID");
            map.put("enterpriseID", enterpriseID);
            String clientIPAddresss = root.elementTextTrim("clientIPAddresss");
            map.put("clientIPAddresss", clientIPAddresss);
            String authType = root.elementTextTrim("authType");
            map.put("authType", authType);
            String credential = root.elementTextTrim("credential");
            map.put("credential", credential);
            String account = root.elementTextTrim("account");
            map.put("account", account);
            String pwd = root.elementTextTrim("pwd");
            map.put("pwd", pwd);
            String remark1 = root.elementTextTrim("remark1");
            map.put("remark1", remark1);
            String remark2 = root.elementTextTrim("remark2");
            map.put("remark2", remark2);
        }
        catch (DocumentException e)
        {
            LOGGER.error("Please check the incoming message:" + "\n\r" + MaskUtils.maskXMLElementValue(xml, "pwd"));
            LOGGER.error("", e);
        }
        
        return map;
    }
}
