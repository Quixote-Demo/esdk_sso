package com.huawei.esdk.sso.bean;

public class DelegateAuthReqBean
{
    private String enterpriseID;
    
    private String clientIPAddresss;
    
    private String authType;
    
    private String credential;
    
    private String account;
    
    private String pwd;
    
    private String remark1;
    
    private String remark2;

    public String getEnterpriseID()
    {
        return enterpriseID;
    }

    public void setEnterpriseID(String enterpriseID)
    {
        this.enterpriseID = enterpriseID;
    }

    public String getClientIPAddresss()
    {
        return clientIPAddresss;
    }

    public void setClientIPAddresss(String clientIPAddresss)
    {
        this.clientIPAddresss = clientIPAddresss;
    }

    public String getAuthType()
    {
        return authType;
    }

    public void setAuthType(String authType)
    {
        this.authType = authType;
    }

    public String getCredential()
    {
        return credential;
    }

    public void setCredential(String credential)
    {
        this.credential = credential;
    }

    public String getAccount()
    {
        return account;
    }

    public void setAccount(String account)
    {
        this.account = account;
    }

    public String getPwd()
    {
        return pwd;
    }

    public void setPwd(String pwd)
    {
        this.pwd = pwd;
    }

    public String getRemark1()
    {
        return remark1;
    }

    public void setRemark1(String remark1)
    {
        this.remark1 = remark1;
    }

    public String getRemark2()
    {
        return remark2;
    }

    public void setRemark2(String remark2)
    {
        this.remark2 = remark2;
    }
}
