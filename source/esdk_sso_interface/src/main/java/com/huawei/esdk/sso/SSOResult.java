package com.huawei.esdk.sso;

public class SSOResult
{
    /*
     * 用户标识
     */
    private String uid;
    
    /*
     * 认证信息，如ticket
     */
    private String credential;
    
    /*
     * 备注信息，可作为后续扩展
     */
    private String remark1;
    
    /*
     * 备注信息，可作为后续扩展
     */
    private String remark2;

    public String getUid()
    {
        return uid;
    }

    public void setUid(String uid)
    {
        this.uid = uid;
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
