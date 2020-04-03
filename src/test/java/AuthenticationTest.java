import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.realm.text.IniRealm;
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

    /**
     * 通过.ini配置文件的方式验证
     */
    @Test
    public void testAutentication1() {
        IniRealm iniRealm = new IniRealm("classpath:user.ini");
        //1.构建Security Manager环境（Security Manager是用来提供安全服务的，所以在做shiro认证的时候要先创建此对象,创建Security Manager对象之后要设置Realm）
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(iniRealm);
        //2.获取向Security Manager提交请求的subject，而主体subject可以通过shiro提供的一个工具类SecurityUtils来获取
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        //使用SecurityUtils之前要设置Security Manager环境
        Subject subject = SecurityUtils.getSubject();
        //3.主体Subject提交请求给Security Manager --> subject.login(token);
        UsernamePasswordToken token = new UsernamePasswordToken("xiehuaxin","123456");
        //提交请求时需要一个token，所以要先创建token
        subject.login(token);
        //4. shiro提供了一个检查主体subject是否认证的方法isAuthenticated(),此方法的返回结果是一个boolean值
        System.out.println(subject.isAuthenticated());
        subject.checkRoles("admin");
        subject.checkPermission("user:delete");
    }

}
