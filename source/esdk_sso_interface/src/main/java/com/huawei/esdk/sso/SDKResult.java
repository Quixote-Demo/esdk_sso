package com.huawei.esdk.sso;

public class SDKResult<T>
{
    private String resultCode;

    private T result;

    public T getResult()
    {
        return result;
    }

    public void setResult(T result)
    {
        this.result = result;
    }

    public String getResultCode()
    {
        return resultCode;
    }

    public void setResultCode(String resultCode)
    {
        this.resultCode = resultCode;
    }


}
