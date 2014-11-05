package com.huawei.esdk.sso.bean;

public class UserInfo
{
    private String product;
    
    private String name;
    
    private String pass;

    public String getProduct()
    {
        return product;
    }

    public void setProduct(String product)
    {
        this.product = product;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public String getPassword()
    {
        return this.pass;
    }

    public void setPassword(String pass)
    {
        this.pass = pass;
    }
}
