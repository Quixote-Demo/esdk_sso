package com.huawei.esdk.sso.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

import com.huawei.esdk.platform.common.config.ConfigManager;
import com.huawei.esdk.platform.common.utils.MaskUtils;
import com.huawei.esdk.platform.common.utils.StringUtils;
import com.huawei.esdk.sso.SSOAuthProcessor;
import com.huawei.esdk.sso.SSOResult;
import com.huawei.esdk.sso.service.ISSOService;
import com.huawei.esdk.sso.service.SSOXMLService;

public class SSOXMLServlet extends HttpServlet
{
    /*
     * Serialization UID
     */
    private static final long serialVersionUID = 1L;
    
    protected static final Logger LOGGER = Logger.getLogger(SSOXMLServlet.class);
    
    private ISSOService ssoService;
    
    private List<String> ips = new ArrayList<String>();
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException
    {
        LOGGER.info("message received");
        String ip = req.getRemoteHost();
        String result = "";
        
        InputStream is = null;
        OutputStream os = null;
        
         LOGGER.info("IP：" + ip);
        try
        {
            if (!ips.contains(ip))
            {
                result = ssoService.buildResMsgBody("2", new SSOResult());
                LOGGER.warn("The ip :" + ip + " is not allowed to access eSDK SSO service.");
            }
            else
            {
                is = req.getInputStream();
                String message = inputStream2String(is);
                LOGGER.debug("The request xml message is :" + MaskUtils.maskXMLElementValue(message, "pwd"));
                result = ssoService.ssoAuth(message);
                LOGGER.debug("The response xml message is " + result);
            }
            
        }
        catch (Exception e)
        {
            LOGGER.error(e.getMessage(), e);
            result = ssoService.buildResMsgBody("-1", new SSOResult());
        }
        finally
        {
            try
            {
                if (null != is)
                {
                    is.close();
                }
            }
            catch (IOException e)
            {
                LOGGER.error(e);
            }
        }
        
        try
        {
            os = resp.getOutputStream();
            os.write(result.getBytes("UTF-8"));
        }
        catch (IOException e)
        {
            LOGGER.error(e);
        }
        finally
        {
            try
            {
                if (null != os)
                {
                    os.close();
                }
            }
            catch (IOException e)
            {
                LOGGER.error(e);
            }
        }
        LOGGER.info("message processed");
    }
    
    /**
     * init sso servlet 的同时读取配置文件中的鉴权IP信息，用反射获取鉴权接口的实现
     */
    @Override
    public void init(ServletConfig config)
        throws ServletException
    {
        String authIPs = StringUtils.avoidNull(ConfigManager.getInstance().getValue("auth_ips"));
        String[] hosts = authIPs.split(",");
        for (String host : hosts)
        {
            ips.add(host);
        }
        
        ssoService = SSOXMLService.getInstance();
        
        String className = ConfigManager.getInstance().getValue("sso_auth_processor");
        try
        {
            Class<?> clz = Class.forName(className);
            try
            {
                SSOAuthProcessor authProcessor = (SSOAuthProcessor)clz.newInstance();
                ssoService.registerSSOAuthProcessor(authProcessor);
            }
            catch (InstantiationException e)
            {
                LOGGER.error(e);
            }
            catch (IllegalAccessException e)
            {
                LOGGER.error(e);
            }
        }
        catch (ClassNotFoundException e)
        {
            LOGGER.error(e);
        }
    }
    
    /**
     * 
     * 输入流转化为string
     *
     * @param is
     * @return
     * @throws IOException    
     * @since eSDK Solution Platform SSO V1R3C10
     */
    private String inputStream2String(InputStream is)
        throws IOException
    {
        return IOUtils.toString(is, Charset.forName("UTF-8"));
    }   
}
