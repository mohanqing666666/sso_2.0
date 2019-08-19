package com.baomidou.kisso.jfinal;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;

import com.alibaba.fastjson.JSON;
import com.baomidou.kisso.AuthToken;
import com.baomidou.kisso.SSOConfig;
import com.baomidou.kisso.SSOHelper;
import com.baomidou.kisso.SSOToken;
import com.baomidou.kisso.Token;
import com.baomidou.kisso.common.SSOProperties;
import com.baomidou.kisso.common.encrypt.RSA;
import com.baomidou.kisso.common.util.Base64Util;
import com.baomidou.kisso.common.util.HttpUtil;
import com.baomidou.kisso.web.waf.request.WafRequestWrapper;
import com.jfinal.core.Controller;
import com.jfinal.kit.JsonKit;


/**
 * 登录
 */
public class LoginController extends Controller {
	/**
	 * 
	
	* <p>Title: LoginController.java</p>  
	
	* <p>Description:认证中心登录验证 </p>  
	
	
	* @author moshuai
	 * @throws Exception 
	 * @date 2019年8月11日
	 */
	public void index() throws Exception {
		SSOProperties prop = SSOConfig.getSSOProperties();
		String returnUrl=this.getPara(SSOConfig.getInstance().getParamReturl());//因为XXXXX处记录了，所以此处可以取到。
		Token token = SSOHelper.getToken(getRequest());
		if (token == null) {
			/**
			 * 正常登录 需要过滤sql及脚本注入
			 */
			WafRequestWrapper wr = new WafRequestWrapper(getRequest());
			String name = wr.getParameter("name");
			String password = wr.getParameter("password");
			if (name !=null) {
				/*
				 * 设置登录 Cookie
				 * 最后一个参数 true 时添加 cookie 同时销毁当前 JSESSIONID 创建信任的 JSESSIONID
				 */
				SSOToken st = new SSOToken(getRequest(), name);
				SSOHelper.setSSOCookie(getRequest(), getResponse(), st, true);
				// 重定向到指定地址 returnUrl
				if (StringUtils.isEmpty(returnUrl)) {
					returnUrl = "/demo/index.html";
				} else {
					returnUrl = HttpUtil.decodeURL(returnUrl);
				}
			    String tk=JSON.toJSONString(st);
//			    st.jsonToken();
				byte[] encryptBytes = RSA.encryptByPrivateKey(tk.getBytes(), prop.get("sso.defined.sso_private_key"));
				String encryptStr = Base64Util.encode(encryptBytes);
				System.out.println("私钥加密结果： " + encryptStr);
				redirect(returnUrl+"?token="+URLEncoder.encode(encryptStr, "UTF-8"));
				return;
			}else {
					if (StringUtils.isNotEmpty(returnUrl)) {
						setAttr("ReturnURL", returnUrl);
					}
					render("login.html");
					 return;
			}
		}else {
			if (StringUtils.isEmpty(returnUrl)) {
				returnUrl = "/demo/index.html";
			}
			 redirect(returnUrl);
			 return;
		}
		
	}
	
}
