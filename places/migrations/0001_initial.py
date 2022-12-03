

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Place',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('place_name', models.CharField(max_length=50, verbose_name='장소명')),
                ('category', models.CharField(default='', max_length=20, verbose_name='카테고리')),
                ('rating', models.DecimalField(decimal_places=2, default=0, max_digits=3, verbose_name='별점')),
                ('place_address', models.CharField(max_length=100, verbose_name='주소')),
                ('place_number', models.IntegerField(verbose_name='장소 전화번호')),
                ('place_time', models.DateField(blank=True, default='', verbose_name='영업 시간')),
                ('place_category', models.CharField(max_length=50, verbose_name='카테고리')),
                ('place_img', models.TextField(verbose_name='장소 이미지')),
                ('latitude', models.FloatField(blank=True, null=True, verbose_name='위도')),
                ('longitude', models.FloatField(blank=True, null=True, verbose_name='경도')),
                ('munu', models.CharField(blank=True, max_length=255, null=True, verbose_name='메뉴')),
            ],
            options={
                'db_table': 'places',
            },
        ),
    ]
