## 1. 安装django-rest-swagger

## 2. 配置项目/settings
```
INSTALLED_APPS = [
  ...
  'rest_framework',
  'rest_framework_swagger',
  'other apps',
]

REST_FRAMEWORK = [
  'DEFAULT_SCHEMA_CLASS': 'rest_framework.schemas.AutoSAchema'
]

## 3. 配置项目/urls
from rest_framework.schemas import get_schema_view
from rest_framework_swagger.renderers import SwaggerUIRenderer, OpenAPIRenderer

schema_view = get_schema_view(title='page title', renderer_classes=[OpenAPIRenderer, SwaggerUIRenderer])

urlpatterns = [
  url(r'api1/$', api1_name),
  ...
  url(r'apin/$', apin_name),
  url(r'docs/$', schema_view),
]

```

## 4. 编辑app/views.py
```
# 函数形式
import coreapi
import coreschema
from rest_framework.decorators import api_view, schema
from rest_framework.response import Response
from rest_framework.schemas import AutoSchema

@api_view(['POST', 'GET'])  # 请求方法，对应swagger界面上显示的请求方法分类
@schema(AutoSchema(manual_fields=[
  coreapi.Field(name='q', location='query', required=True, schema=chreschema.String(description='search value')),
  coreapi.Field(name='page', location='query', schema=coreschema.Integer(description='page'))
]))
def api1_name(request):
  q = request.GET.get('q')
  return Response({
    'r': q
  })
```
```
@类形式
from rest_framework.views import APIView
from rest_framework.response import Response
class MyApi(APIView):  # 继承APIView，而不是继承默认的View
  
  schema = AutoSchema(manual_fields=[
    coreapi.Field(),
    coreapi.Field()  # 同函数式
  ])
  
  def get(self, request):
    return Response({
      'myapi': 'myapi'
    })
```
