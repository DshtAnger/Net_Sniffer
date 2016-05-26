#coding:utf-8
from django.shortcuts import render
from django_web.models import *
from django.core.paginator import Paginator
import json
from threading import *
from capture_packets import capturing,GlobalControl
# Create your views here.

def data_column():
    '''
    return as :
    [{u'data': [7744], u'name': 'TCP'},
     {u'data': [0, 4143], u'name': 'TCP HTTP'},
     {u'data': [0, 0, 304], u'name': 'UDP DNS'},
     {u'data': [0, 0, 0, 68], u'name': 'Other'}]
    '''
    pipeline = [
        {'$match':{'fourthlayer_type':{'$exists':1}}},
        {'$group':{'_id':'$fourthlayer_type','count':{'$sum':1}}},
        {'$sort':{'count':-1}}]
    data = []
    zero_count = 0
    for i in PacketsInfo._get_collection().aggregate(pipeline):
        data.append({'name':str(i['_id']),'data':[0]*zero_count+[i['count']]})
        zero_count += 1
    return data



def data_pie():
    '''
    return as:
    [['TCP',TCP],
    ['UDP',UDP],
    ['DNS',DNS],
    ['HTTP',HTTP],
    ['Other',Other]]
    '''
    pipeline = [ 
        {'$match':{'fourthlayer_type':{'$exists':1}}},
        {'$group':{'_id':'$fourthlayer_type','y':{'$sum':1}}},
        {'$sort':{'y':-1}}]
    data = [[str(i['_id']),i['y']] for i in PacketsInfo._get_collection().aggregate(pipeline)]
    return data
    

record_start = None
recore_stop = None
def packets(request):
    global record_start
    global recore_stop

    control_info = request.GET.get('control')

    # #调试信息
    # print 'control_info:',control_info
    # print 'record_start:',record_start
    # print 'recore_stop:',recore_stop
    # print 'if_stopCapturing:',GlobalControl.if_stopCapturing,"id:",id(GlobalControl.if_stopCapturing)
    # print '--------------------------------'

    if (control_info=='1' and record_start==None ):
        recore_stop = None
        record_start = '1'
        GlobalControl.if_stopCapturing = 0
        t = Thread(target=capturing,args=())        
        t.start()
        #print "点击了开始,开始抓包"
    elif (control_info=='1' and record_start=='1' and recore_stop==None):
        #do nothing
        pass
        #print "已经点击了开始,不能再开始,可以点击停止"
    elif (control_info=='0' and record_start=='1' and recore_stop==None):
        recore_stop = '1'
        record_start=None
        GlobalControl.conto = 1
        #print "点击了停止,停止抓包"
    elif (control_info=='0' and recore_stop=='1'):
        #do nothing
        pass
        #print "已经点击了停止,不能再停止,可以点击开始"

    limit = 20
    packet_info = PacketsInfo.objects

    paginatior = Paginator(packet_info,limit)
    page = request.GET.get('page',1)
    loaded = paginatior.page(page)
    
    context = {
            'packets':loaded,
            'series_column':data_column(),
            'series_pie':data_pie()

    }

    return render(request, "packets.html",context)
