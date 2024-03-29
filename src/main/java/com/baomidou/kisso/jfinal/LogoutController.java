package com.baomidou.kisso.jfinal;

import com.baomidou.kisso.SSOHelper;
import com.jfinal.core.Controller;

/**
 * 登录
 */
public class LogoutController extends Controller {
/**
 * 

* <p>Title: LogoutController.java</p>  

* <p>Description: 退出登录</p>  


* @author moshuai

* @date 2019年8月11日
 */
	public void index() {
		/**
		 * <p>
		 * SSO 退出，清空退出状态即可
		 * </p>
		 * 
		 * <p>
		 * 子系统退出 SSOHelper.logout(request, response); 注意 sso.properties 包含 退出到
		 * SSO 的地址 ， 属性 sso.logout.url 的配置
		 * </p>
		 */
		SSOHelper.clearLogin(getRequest(), getResponse());
		render("logout.html");
		
	}

}
