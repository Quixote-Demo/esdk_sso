package com.huawei.esdk.sso.bean;

import java.util.List;


public class ProdAcctPwdResBean
{
    private String resCode;
    
    private List<UserInfo> userinfo;
    
    public String getResCode()
    {
        return resCode;
    }
    
    public void setResCode(String resCode)
    {
        this.resCode = resCode;
    }
    
    public List<UserInfo> getUserinfo()
    {
        return userinfo;
    }
    
    public void setUserinfo(List<UserInfo> userinfo)
    {
        this.userinfo = userinfo;
    }
}
