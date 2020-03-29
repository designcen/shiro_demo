import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Before;
import org.junit.Test;


/**
 * 授权测试
 * @author cenkang
 * @date 2020/3/28 - 23:39
 */
public class AuthorizationTest {
    SimpleAccountRealm simpleAccountRealm = new SimpleAccountRealm();
    @Before // 在方法开始前添加一个用户，让他有两个角色admin和user
    public void addUser(){
        simpleAccountRealm.addAccount("xiaoming","123456","admin","user");
    }

    @Test
    public void testAuthorization(){
        // 1.构建securityManager环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(simpleAccountRealm);
        // 2.主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager); // 设置securityManager环境
        Subject subject = SecurityUtils.getSubject(); // 获取当前主体
        UsernamePasswordToken token = new UsernamePasswordToken("xiaoming","123456");
        subject.login(token); // 登陆
        // subject.isAuthenticated()方法返回一个boolean值,用于判断用户是否认证成功
        System.out.println("isAuthenticated:" + subject.isAuthenticated()); // 输出true
        // 判断subject是否具有admin和user两个角色权限,如没有则会报错
        subject.checkRoles("admin","user");
    }
}
