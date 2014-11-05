package com.huawei.esdk.sso.bean;

import java.util.HashMap;
import java.util.Map;

public class ErrorMaps
{
    
    public Map<String, String> map = new HashMap<String, String>();
    
    /**
     * 供Digester调用的方法
     * @param errorMap
     */
    public void addMap(ErrorMapBean errorMapBean)
    {
        this.map.put(errorMapBean.getUaap(), errorMapBean.getEsdk());
    }
    
    public String findMappedErr(String uaap)
    {
        return map.get(uaap);
    }
}
