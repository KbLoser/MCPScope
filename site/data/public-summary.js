window.MCPSCOPE_PUBLIC_SUMMARY = {
  "schema_version": 2,
  "publication": {
    "label": "619 条漏洞记录的脱敏汇总",
    "raw_targets_published": false,
    "record_definition": "按最新 CSV 中的工具记录统计，不代表每条记录都已完成影响级别验证。"
  },
  "headline": {
    "services": 619,
    "records": 619,
    "unique_tools": 457,
    "findings": 619,
    "categories": 10
  },
  "candidate_risk_types": [
    {
      "label": "文件与内容存储",
      "value": 191
    },
    {
      "label": "通信与公开发布",
      "value": 96
    },
    {
      "label": "主机与代码执行",
      "value": 83
    },
    {
      "label": "数据库访问与操作",
      "value": 74
    },
    {
      "label": "服务端网络访问",
      "value": 74
    },
    {
      "label": "身份、权限与账户生命周期",
      "value": 65
    },
    {
      "label": "业务交易与支付",
      "value": 13
    },
    {
      "label": "业务对象删除与撤销",
      "value": 13
    },
    {
      "label": "云与基础设施管理",
      "value": 5
    },
    {
      "label": "工作流与软件安装",
      "value": 5
    }
  ],
  "record_sources": [
    {
      "label": "无认证扫描累计",
      "value": 559
    },
    {
      "label": "IP 地址工具数据",
      "value": 44
    },
    {
      "label": "Curl 协议复测",
      "value": 16
    }
  ],
  "finding_categories": [
    {
      "label": "文件与内容存储",
      "value": 191
    },
    {
      "label": "通信与公开发布",
      "value": 96
    },
    {
      "label": "主机与代码执行",
      "value": 83
    },
    {
      "label": "数据库访问与操作",
      "value": 74
    },
    {
      "label": "服务端网络访问",
      "value": 74
    },
    {
      "label": "身份、权限与账户生命周期",
      "value": 65
    },
    {
      "label": "业务交易与支付",
      "value": 13
    },
    {
      "label": "业务对象删除与撤销",
      "value": 13
    },
    {
      "label": "云与基础设施管理",
      "value": 5
    },
    {
      "label": "工作流与软件安装",
      "value": 5
    }
  ],
  "case_studies": [
    {
      "id": "CASE-STORAGE-01",
      "category": "文件与内容存储",
      "title": "文件与内容存储是最大类别",
      "summary": "最新记录中有 191 条工具被归入文件与内容存储。公开结果只保留能力分类，不公开目标、请求和响应。",
      "evidence": "能力分类记录"
    },
    {
      "id": "CASE-COMMS-01",
      "category": "通信与公开发布",
      "title": "通信与公开发布是第二大类别",
      "summary": "有 96 条记录涉及消息、邮件或公开发布能力。该类别表示工具可以改变外部通信状态，不等于已经证明业务影响。",
      "evidence": "能力分类记录"
    },
    {
      "id": "CASE-EXEC-01",
      "category": "主机与代码执行",
      "title": "主机与代码执行需要优先复核",
      "summary": "有 83 条记录被归入主机与代码执行。这是能力层面的高风险信号，实际可达性和影响仍需授权测试。",
      "evidence": "能力分类记录"
    },
    {
      "id": "CASE-DATABASE-01",
      "category": "数据库访问与操作",
      "title": "数据库访问是稳定出现的高风险类别",
      "summary": "有 74 条记录涉及数据库访问与操作。结果仅展示统计与分类，不包含查询、连接信息或可复现载荷。",
      "evidence": "能力分类记录"
    }
  ],
  "limitations": [
    "619 条记录来自工具能力筛选与复测汇总，不等同于 619 条都已完成影响验证。",
    "筛选方式以工具名称或描述关键词为主，命名、描述和 Schema 覆盖不足会造成漏报。",
    "匿名获取工具列表不代表工具调用不需要认证，认证状态仍需在授权范围内单独核验。",
    "公开页面只展示聚合类别和来源，不发布目标地址、凭据、原始响应或可复现参数。"
  ]
};
