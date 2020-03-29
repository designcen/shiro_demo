import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Before;
import org.junit.Test;

/**
 * 验证测试
 * @author cenkang
 * @date 2020/3/28 - 22:58
 */
public class AuthenticationTest {
    SimpleAccountRealm simpleAccountRealm = new SimpleAccountRealm();
    @Before // 在方法开始前添加一个用户
    public void addUser(){
        simpleAccountRealm.addAccount("xiaoming","123456");
    }
    @Test
    public void testAuthentication() {
        // 1.构建SecurityManager环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(simpleAccountRealm);
        // 2.主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager); // 设置securitymanager环境
        Subject subject = SecurityUtils.getSubject(); // 获取当前主体
        UsernamePasswordToken token = new UsernamePasswordToken("xiaoming","123456");
        subject.login(token); // 登陆
        // subject.isAuthenticated(); // 返回判断用户是否认证成功
        System.out.println( subject.isAuthenticated());
        subject.logout(); // 登出
        System.out.println(subject.isAuthenticated());



    }
}
