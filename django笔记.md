#### 1. 用更强大的xadmin替代自带的admin。xadmin安装方法：
```
pip install git+git://github.com/sshwsfc/xadmin.git@django2
```

#### 2. settings常用设置
```
LANGUAGE_CODE = 'zh-hans'

TIME_ZONE = 'Asia/Shanghai'

USE_TZ = False

# 设置静态资源路径
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]

# 使用自定义的auth方法，默认方法只支持账号+密码登录，自定义后可以支持账号/邮箱/手机号+密码等更灵活的方式登录
# 需要配合views里面重写默认方法，前台可以用user.is_authenticated来判断是否登录成功
AUTHENTICATION_BACKENDS = (
    'users.views.CustomBackend',
)

# users.views.py
class CustomBackend(ModelBackend):
    # 重写authenticate方法
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            # 这里的Q方法，可以用或/与等逻辑写查询条件
            # user.check_password()方法为默认方法，检查密码是否匹配。
            user = UserProfile.object.get(Q(username=username) | Q(email=username))
            if user.check_password(password):
                return user
        except Exception as e:
            return None

# index.html
{% if request.user.is_authenticated %}
html code
{% else %}
html code
{% endif %}

# 替换默认的user表，使用自定义
AUTH_USER_MODEL = 'users.UserProfile'

```

#### 3. models常用方法
```
# model需要继承models.Model类
class UserProfile(models.Model):
    # 定义字段
    
    class Meta:
        # 配置Meta，这2个字段是后台显示时的表名
        verbose_name = '表名'
        verbose_name_plural = verbose_name
    
    def __str__(self):
        # 配置返回字段。默认是返回一个对象。配置之后，则在查询时，默认返回改字段。
        return self.字段名

# 字段类型
CharField -- 字符串，需要指定最大长度
TextField -- 文本，无需定义长度
IntegerField -- 整数
ImageField -- 图片。此处在db中存放图片路径，需要指定upload_to参数
DateTimeField -- 日期时间。通常给每个表加上这个字段，默认取系统时间，存放记录的变更时间。
DateField -- 日期类型。只有日期，没有时间。
FileField -- 上传文件的字段。
EmailField -- 邮件。会自动校验是否符合邮件规则。
URLField -- 存放url。会自动校验是否符合规则。
ForeignKey -- 外键。需要指定关联的表名，以及on_delete参数

# 字段关键参数
verbose_name -- 别名。所有字段都有，在后台中展示别名，而不是默认的英文名。
default=datetime.now -- 默认值。
null=True, blank=True -- 是否可以为空。
upload_to='directory/%Y/%m' -- 上传路径。适用于FileField/ImageField。通常用在上传图片/文件等功能。
本例的意思是上传到directory路径下4位数年子目录下2位数月子目录。目录不存在时会自动创建。
choices=(('m', '男'), ('f', '女')) -- 选择约束。元组类型，两个元组子元素表示有2个选项。其中子元素也是元组类型，第一个字段表示数据库存储的实际值，第二个字段表示后台展示的值。
在本例中，后台展示为由‘男’/‘女’组成的下拉列表，选中后存储时，数据库中存储的是对应的'm'/'f'。
on_delete=models.CASCADE -- 外键需要设置。表示所关联的主键删除时，外键如何处理。取值有以下：
    CASCADE -- 删除外键关联数据
    SET_NULL -- 设置外键数据为空（前提需要外键字段允许为空）
    PROTECT -- 不允许删除主键，抛出错误
    SET_DEFAULT -- 设置外键数据为默认数据（同样前提是改字段有默认值）
```
#### 4. 后台注册model，注册后可以登录后台在页面对表进行操作。
这里直接使用xadmin的后台管理，与默认的admin基本相同。
```
class CityAdmin:
    list_display = []  # 在后台中展示哪些字段
    list_filter = []  # 哪些字典放入过滤选项
    search_fields = []  # 哪些字段放入搜索选项，这里通常不放入时间，因为由于时间格式问题，容易出错。

xadmin.site.register(City, CityAdmin)
```

#### 5. 全局配置
```
# 启用xadmin的主题管理。把这个类放在某个app下的adminx.py文件，并注册到xadmin
class BaseSetting:
    enable_themes = True
    use_bootswatch = True


class GlobalSettings:
    # 配置标题和页尾
    site_title = 'My Title'
    site_footer = 'My Footer'
    # 配置菜单可折叠
    menu_style = 'accordion'


xadmin.site.register(views.BaseAdminView, BaseSetting)
xadmin.site.register(views.CommAdminView, GlobalSettings)
```
```
# 配置菜单中文显示


# 1.在app下的apps.py文件中，写入需要展示的别名
class UserConfig(AppConfig):
    name = 'users'
    verbose_name = '用户管理'
# 2.在app下的__init__.py文件中写入默认配置
default_app_config = 'users.apps.UserConfig'
```
#### 6. 用户模型 [对django的User模型和四种扩展/重写方法小结](https://www.jb51.net/article/167864.htm)
```
正式项目一定提前考虑好用户模型，可以多设置几个备用字段。一旦初始化数据库之后，不能修改默认的用户模型，除非重建数据库，导致数据丢失。

```




