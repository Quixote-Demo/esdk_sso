package com.huawei.esdk.sso.service;

import java.io.IOException;

import org.apache.commons.digester3.Digester;
import org.apache.log4j.Logger;
import org.xml.sax.SAXException;

import com.huawei.esdk.sso.SSOAuthProcessor;
import com.huawei.esdk.sso.bean.ErrorMapBean;
import com.huawei.esdk.sso.bean.ErrorMaps;

public abstract class AbstractService
{
    private static final Logger LOGGER = Logger.getLogger(AbstractService.class);
    
    protected SSOAuthProcessor processor;
    
    protected ErrorMaps errorCodeMapping;
    
    public AbstractService()
    {
        loadErrorCode();
    }
    
    public void registerSSOAuthProcessor(SSOAuthProcessor processor)
    {
        this.processor = processor;
    }
    
    /**
     * 加载错误码映射文件
     * @since eSDK Solution Platform V1R3C10
     */
    private void loadErrorCode()
    {
        if (null != errorCodeMapping)
        {
            return;
        }
        Digester digester = new Digester();
        digester.setValidating(false);
        digester.addObjectCreate("errors", ErrorMaps.class);
        // 指明匹配模式和要创建的类
        digester.addObjectCreate("errors/error", ErrorMapBean.class);
        digester.addBeanPropertySetter("errors/error/uaap", "uaap");
        digester.addBeanPropertySetter("errors/error/eSDK", "esdk");
        
        // 当移动到下一个标签中时的动作
        digester.addSetNext("errors/error", "addMap");
        
        try
        {
            ClassLoader cl = this.getClass().getClassLoader();
            if (null != cl)
            {
                errorCodeMapping = digester.parse(cl.getResourceAsStream("ssoserver_esdk_errorcode_mapping.xml"));
            }
        }
        catch (IOException e)
        {
            LOGGER.error("", e);
        }
        catch (SAXException e)
        {
            LOGGER.error("", e);
        }
    }
    
    protected String getEsdkErrorCode(String ssoErrorCode)
    {
        String resCode = errorCodeMapping.findMappedErr(ssoErrorCode);
        if (null == resCode)
        {
            resCode = ssoErrorCode;
        }
        if (null == resCode)
        {
            resCode = "-1";
        }
        
        return resCode;
    }
}
