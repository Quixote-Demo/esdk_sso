package com.huawei.esdk.sso.servlet;

import java.io.IOException;
import java.io.OutputStream;
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
import com.huawei.esdk.sso.service.SSORestDelegateService;

public class SSORestServlet extends HttpServlet
{
    /*
     * Serialization UID
     */
    private static final long serialVersionUID = 1L;
    
    protected static final Logger LOGGER = Logger.getLogger(SSOXMLServlet.class);
    
    private ISSOService ssoServiceDelegate;
    
    private List<String> ips = new ArrayList<String>();
    
    private String processRequest(HttpServletRequest req)
    {
        LOGGER.debug("message received");
        String ip = req.getRemoteHost();
        String result = "";
        
        try
        {
            if (!ips.contains(ip))
            {
                result = ssoServiceDelegate.buildResMsgBody("2", new SSOResult());
                LOGGER.warn("the ip :" + ip + "is not allowed to SSO");
            }
            else
            {
                String message = IOUtils.toString(req.getInputStream());
                LOGGER.debug("The incoming message is :" + MaskUtils.maskJson(message, "pwd"));
                result = ssoServiceDelegate.ssoAuth(message);
                LOGGER.debug("The response message is " + result);
            }
        }
        catch (Exception e)
        {
            LOGGER.error("", e);
            result = ssoServiceDelegate.buildResMsgBody("-1", new SSOResult());
        }
        
        return result;
    }
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException
    {
        OutputStream os = null;
        try
        {
            String result = processRequest(req);
            resp.setContentType("application/json");
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
    }
    
    public void init(ServletConfig config)
        throws ServletException
    {
        String authIPs = StringUtils.avoidNull(ConfigManager.getInstance().getValue("auth_ips"));
        String[] hosts = authIPs.split(",");
        for (String host : hosts)
        {
            ips.add(host);
        }
        
        ssoServiceDelegate = SSORestDelegateService.getInstance();
        
        String className = ConfigManager.getInstance().getValue("sso_auth_processor");
        
        String errorMsg =
            "Registeration the implementation of SSOAuthProcessor failed, please check the configuration.";
        try
        {
            Class<?> clz = Class.forName(className);
            Object obj = clz.newInstance();
            SSOAuthProcessor authProcessor = (SSOAuthProcessor)obj;
            ssoServiceDelegate.registerSSOAuthProcessor(authProcessor);
        }
        catch (ClassNotFoundException e)
        {
            LOGGER.error(errorMsg);
            LOGGER.error(e);
        }
        catch (InstantiationException e)
        {
            LOGGER.error(errorMsg);
            LOGGER.error(e);
        }
        catch (IllegalAccessException e)
        {
            LOGGER.error(e);
        }
    }
}
