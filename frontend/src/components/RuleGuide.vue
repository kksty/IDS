<template>
  <div class="rule-guide">
    <div class="guide-header">
      <div class="header-wrapper">
        <div class="header-title">
          <el-icon class="title-icon"><Document /></el-icon>
          <span>规则填写说明书</span>
        </div>
        <div class="header-actions">
          <el-button @click="goBack" type="primary">
            <el-icon><ArrowLeft /></el-icon>
            返回规则管理
          </el-button>
        </div>
      </div>
    </div>

    <div class="guide-content">
      <el-card class="guide-card" shadow="never">
        <template #header>
          <div class="card-title">
            规则字段说明（以“创建/编辑规则”对话框为准）
          </div>
        </template>
        <p>
          规则创建/编辑对话框分为“基本信息”、“网络匹配”、“内容匹配”等部分。下面逐项说明各字段含义和填写建议。
        </p>
      </el-card>

      <el-card class="guide-card" shadow="never">
        <template #header>
          <div class="card-title">基本信息</div>
        </template>

        <el-descriptions :column="1" border>
          <el-descriptions-item
            label="规则ID（rule_id）"
            label-class-name="desc-label"
          >
            <div>
              <strong>作用：</strong>规则唯一标识，系统用它来识别并存储规则。
            </div>
            <div>
              <strong>填写建议：</strong>使用整数并确保不重复；建议从 1000000
              以上开始，避免与内置规则冲突。
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="告警名称（msg/name）"
            label-class-name="desc-label"
          >
            <div>
              <strong>作用：</strong>告警展示时的标题，便于快速判断告警含义。
            </div>
            <div>
              <strong>填写建议：</strong
              >简洁明了，例如“SSH爆破检测”、“可疑Web扫描”。
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="分类（classtype）"
            label-class-name="desc-label"
          >
            <div><strong>作用：</strong>告警分类，用于过滤、统计和展示。</div>
            <div>
              <strong>填写建议：</strong>按攻击类型选择，如
              attempt-admin、web-application-attack、network-scan 等。
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="版本（rev）"
            label-class-name="desc-label"
          >
            <div>
              <strong>作用：</strong>记录规则更新版本，便于追踪历史变更。
            </div>
            <div>
              <strong>填写建议：</strong>修改规则后递增版本号（如 1 →
              2），方便对比和回滚。
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="启用状态（enabled）"
            label-class-name="desc-label"
          >
            <div>
              <strong>作用：</strong
              >控制规则是否生效。关闭后该规则不触发告警，但仍保留配置。
            </div>
            <div>
              <strong>使用场景：</strong
              >临时禁用误报规则，或在配置完成后再启用。
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="标签（tags）"
            label-class-name="desc-label"
          >
            <div><strong>作用：</strong>用于快速搜索/分组规则。</div>
            <div>
              <strong>填写建议：</strong>逗号分隔，例如
              <code>web,sql,injection</code>。
            </div>
          </el-descriptions-item>
        </el-descriptions>
      </el-card>

      <el-card class="guide-card" shadow="never">
        <template #header>
          <div class="card-title">网络匹配字段</div>
        </template>

        <el-descriptions :column="1" border>
          <el-descriptions-item
            label="协议（protocol）"
            label-class-name="desc-label"
          >
            <div>
              <strong>作用：</strong>限制规则仅匹配某类协议（如
              TCP/UDP/ICMP），提高精度。
            </div>
            <div>
              <strong>填写建议：</strong
              >指定具体协议可减少误报；不填写则匹配所有协议。
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="源 IP（src）"
            label-class-name="desc-label"
          >
            <div><strong>作用：</strong>匹配数据包的源 IP 地址范围。</div>
            <div>
              <strong>支持格式：</strong>
              <ul>
                <li><code>any</code>：任意地址</li>
                <li><code>192.168.1.1</code>：单个 IP</li>
                <li><code>192.168.0.0/16</code>：CIDR 网段</li>
                <li><code>[1.1.1.1,2.2.2.2]</code>：列表</li>
                <li><code>!1.1.1.1</code>：排除某个地址</li>
              </ul>
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="目标 IP（dst）"
            label-class-name="desc-label"
          >
            <div><strong>作用：</strong>匹配数据包的目的 IP 地址范围。</div>
            <div>
              <strong>填写建议：</strong>与源 IP 类似写法，适用于指定目标系统。
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="源端口 / 目标端口"
            label-class-name="desc-label"
          >
            <div>
              <strong>作用：</strong>匹配源/目的端口范围，常用于区分服务类型。
            </div>
            <div>
              <strong>支持格式：</strong>
              <ul>
                <li><code>any</code>：任意端口</li>
                <li><code>80</code>：单个端口</li>
                <li><code>80:443</code>：范围</li>
                <li><code>[80,443]</code>：列表</li>
                <li><code>!21</code>：排除</li>
              </ul>
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="方向（direction）"
            label-class-name="desc-label"
          >
            <div>
              <strong>作用：</strong>控制规则匹配时如何解释源/目的关系。
            </div>
            <div>
              <strong>取值：</strong><code>-></code>（单向）或
              <code><></code>（双向）。
            </div>
          </el-descriptions-item>
        </el-descriptions>
      </el-card>

      <el-card class="guide-card" shadow="never">
        <template #header>
          <div class="card-title">内容匹配字段（触发逻辑）</div>
        </template>

        <el-descriptions :column="1" border>
          <el-descriptions-item
            label="忽略大小写（nocase）"
            label-class-name="desc-label"
          >
            <div><strong>作用：</strong>开启后，字符串匹配不区分大小写。</div>
          </el-descriptions-item>

          <el-descriptions-item label="匹配内容" label-class-name="desc-label">
            <div>
              <strong>作用：</strong
              >填写要匹配的内容，可以是文本、正则或二进制（以十六进制表示）。
            </div>
            <div>
              <strong>支持格式：</strong>
              <ul>
                <li><code>文本</code>：如 <code>GET /admin</code></li>
                <li><code>正则</code>：例 <code>/user\d+/</code></li>
                <li>
                  <code>二进制（十六进制表示）</code>：如
                  <code>|00 01|</code> 或
                  <code>\x00</code>，都是通过十六进制表示的字节流。
                </li>
              </ul>
            </div>
          </el-descriptions-item>

          <el-descriptions-item label="匹配类型" label-class-name="desc-label">
            <div>
              <strong>作用：</strong>指定当前条件是“字符串匹配”还是“正则匹配”。
            </div>
            <div>
              <strong>建议：</strong
              >如果规则简单推荐使用字符串匹配（性能更好），复杂场景使用正则。
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="offset / depth / distance / within"
            label-class-name="desc-label"
          >
            <div>
              <strong>作用：</strong
              >用于控制匹配在报文中的位置和范围，帮助提高匹配准确性并避免误报。
            </div>
            <div>
              <strong>offset：</strong
              >从报文开始跳过的字节数，如果你知道目标内容在固定位置，可以用它来起点定位。
            </div>
            <div>
              <strong>depth：</strong>从 offset 开始，搜索的最大字节长度。配合
              offset 可以缩小匹配范围，提高性能和精度。
            </div>
            <div>
              <strong>distance：</strong
              >用于多个匹配条件之间，表示当前条件与上一个条件之间的最小字节间距（只在多条件规则时有意义）。
            </div>
            <div>
              <strong>within：</strong
              >用于多个匹配条件之间，表示当前条件与上一个条件之间的最大字节间距（只在多条件规则时有意义），通常配合
              distance 使用。
            </div>
          </el-descriptions-item>
        </el-descriptions>

        <el-alert type="warning" :closable="false" show-icon>
          <template #title>多条件组合提醒</template>
          <div>
            如果配置了多个匹配条件，它们会以<strong>AND</strong>关系组合，只有全部匹配时才会触发告警。
          </div>
        </el-alert>
      </el-card>

      <el-card class="guide-card" shadow="never">
        <template #header>
          <div class="card-title">高级配置字段</div>
        </template>

        <el-descriptions :column="1" border>
          <el-descriptions-item label="Byte Test" label-class-name="desc-label">
            <div>
              <strong>作用：</strong
              >对报文中指定偏移的字节进行数值比较，用于精确检测协议字段。
            </div>
            <div>
              <strong>使用场景：</strong
              >例如检测TCP头部某位置字段值，或自定义协议的字段。
            </div>
          </el-descriptions-item>

          <el-descriptions-item label="Flow" label-class-name="desc-label">
            <div>
              <strong>作用：</strong>限制规则只在指定会话方向/状态匹配（如
              established、to_client）。
            </div>
            <div class="hint-text">
              <strong>限制说明：</strong>flow 仅对 TCP 全量实现；UDP 为已知限制，flow 条件可能放行。
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="标签 & 优先级"
            label-class-name="desc-label"
          >
            <div><strong>标签：</strong>用于规则搜索、过滤及分组管理。</div>
            <div>
              <strong>优先级：</strong
              >控制告警在列表中的排序，数值越小优先级越高。
            </div>
          </el-descriptions-item>

          <el-descriptions-item
            label="阈值（Threshold）"
            label-class-name="desc-label"
          >
            <div>
              <strong>作用：</strong
              >限制单位时间内规则触发次数，防止短时间爆发性告警。
            </div>
          </el-descriptions-item>
        </el-descriptions>
      </el-card>

      <el-card class="guide-card" shadow="never">
        <template #header>
          <div class="card-title">导入规则说明</div>
        </template>

        <p>
          本系统支持从 Snort 规则文件 (.rules) 或 JSON
          规则数组导入，方便从其他系统迁移或批量创建规则。
        </p>

        <ul>
          <li>
            <strong>Snort导入：</strong
            >上传文件后会解析并显示导入结果，失败条目会在控制台输出错误信息。
          </li>
          <li>
            <strong>JSON导入：</strong>粘贴符合格式的 JSON
            数组（每项为一条规则）即可导入。
          </li>
          <li>
            <strong>注意：</strong>导入时请确保 sid 不重复，否则会覆盖已有规则。
          </li>
        </ul>
      </el-card>

      <el-card class="guide-card" shadow="never">
        <template #header>
          <div class="card-title">常见操作建议</div>
        </template>

        <ul>
          <li>
            <strong>误报排查：</strong
            >先将规则范围缩小（指定IP/端口/匹配位置），确认匹配对象后再放宽范围。
          </li>
          <li>
            <strong>版本管理：</strong>修改规则后请务必更新 rev
            字段，便于后续审计。
          </li>
          <li>
            <strong>标签使用：</strong>给规则添加标签可以大幅提高搜索效率。
          </li>
          <li>
            <strong>定期清理：</strong
            >删除不再使用的规则，保持规则集简洁，提高查找敏捷度。
          </li>
        </ul>
      </el-card>
    </div>
  </div>
</template>

<script>
import { onMounted } from "vue";
import { Document, ArrowLeft } from "@element-plus/icons-vue";

export default {
  name: "RuleGuide",
  components: {
    Document,
    ArrowLeft,
  },
  setup() {
    const goBack = () => {
      window.location.hash = "#/rules";
    };

    onMounted(() => {
      // 页面加载时的处理
    });

    return {
      goBack,
    };
  },
};
</script>

<style scoped>
.rule-guide {
  max-width: 1200px;
  margin: 0 auto;
}

.guide-header {
  background: white;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.header-wrapper {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-title {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 24px;
  font-weight: 600;
  color: #1f2937;
}

.title-icon {
  color: #3b82f6;
}

.header-actions {
  display: flex;
  gap: 12px;
}

.guide-content {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.guide-card {
  margin-bottom: 0;
}

.card-title {
  font-size: 18px;
  font-weight: 600;
  color: #1f2937;
}

.desc-label {
  font-weight: 600;
  background-color: #f8fafc;
  width: 120px;
}

.classtype-list {
  margin: 8px 0;
  padding-left: 20px;
}

.classtype-list li {
  margin-bottom: 4px;
  font-family: "Courier New", monospace;
  font-size: 13px;
}

.classtype-list code {
  background-color: #f1f5f9;
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 12px;
}

pre {
  background-color: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  padding: 16px;
  overflow-x: auto;
  margin: 12px 0;
}

pre code {
  font-family: "Courier New", monospace;
  font-size: 14px;
  color: #1f2937;
  background: none;
  padding: 0;
}

ul {
  margin: 8px 0;
  padding-left: 20px;
}

li {
  margin-bottom: 6px;
  line-height: 1.5;
}

code {
  background-color: #f1f5f9;
  padding: 2px 6px;
  border-radius: 3px;
  font-family: "Courier New", monospace;
  font-size: 13px;
  color: #1f2937;
}

strong {
  color: #1f2937;
}
</style>
