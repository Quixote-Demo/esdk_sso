package com.huawei.esdk.sso.bean;

public class DelegateAuthResBean
{
    private String resCode;
    
    private String UID;
    
    private String credential;
    
    private String remark1;
    
    private String remark2;

    public String getResCode()
    {
        return resCode;
    }

    public void setResCode(String resCode)
    {
        this.resCode = resCode;
    }

    public String getUID()
    {
        return UID;
    }

    public void setUID(String uID)
    {
        UID = uID;
    }

    public String getCredential()
    {
        return credential;
    }

    public void setCredential(String credential)
    {
        this.credential = credential;
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
