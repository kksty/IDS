<template>
  <div class="rules-container">
    <!-- 头部区域 -->
    <div class="rules-header">
      <div class="header-wrapper">
        <div class="header-title">
          <el-icon class="title-icon"><DocumentAdd /></el-icon>
          <span>规则管理</span>
        </div>
        <div class="header-actions">
          <!-- 规则计数显示 -->
          <div class="rules-count-header">
            <el-tag type="info" size="small">{{ totalRules }} 个规则</el-tag>
          </div>
          <!-- 搜索框 -->
          <el-input
            v-model="searchText"
            placeholder="搜索规则ID、名称或描述"
            class="search-input"
            clearable
            @input="handleSearch"
          >
            <template #prefix>
              <el-icon><Search /></el-icon>
            </template>
          </el-input>

          <!-- 筛选器 -->
          <el-input
            v-model="filterCategory"
            placeholder="输入类别搜索"
            class="filter-input"
            clearable
            @input="handleFilter"
          />

          <!-- 标签搜索 -->
          <el-input
            v-model="filterTags"
            placeholder="输入标签搜索"
            class="filter-input"
            clearable
            @input="handleFilter"
          />

          <el-button
            type="primary"
            class="action-btn"
            @click="handleCreateRule"
          >
            <el-icon><Plus /></el-icon><span>创建规则</span>
          </el-button>
          <el-button
            type="success"
            class="action-btn"
            @click="showImportDialog = true"
          >
            <el-icon><Upload /></el-icon><span>导入规则</span>
          </el-button>
          <el-button type="info" class="action-btn" @click="loadRules">
            <el-icon><Refresh /></el-icon><span>刷新</span>
          </el-button>
        </div>
      </div>
    </div>

    <div class="batch-actions" v-if="selectedRules.length > 0 || selectAllMode">
      <el-button
        type="danger"
        @click="batchDeleteRules"
        :loading="batchDeleting"
      >
        <el-icon><Delete /></el-icon>
        删除选中规则 ({{ rulesToDeleteCount }})
      </el-button>
      <el-button type="primary" v-if="!selectAllMode" @click="selectAllRules">
        <el-icon><Check /></el-icon>
        全选全部规则
      </el-button>
      <el-button @click="clearSelection">取消选择</el-button>
      <span v-if="selectAllMode" class="select-all-hint">
        全选模式：总共 {{ allSelectedRuleIds.length }} 条规则， 将删除
        {{ allSelectedRuleIds.length - excludedRules.length }} 条规则， 保留
        {{ excludedRules.length }} 条被取消勾选的规则
      </span>
    </div>

    <!-- 规则列表 -->
    <el-table
      :data="filteredRules"
      stripe
      border
      class="rules-table"
      v-loading="loading"
      @selection-change="handleSelectionChange"
      ref="rulesTableRef"
    >
      <el-table-column type="selection" width="55" align="center" />
      <el-table-column
        label="#"
        width="60"
        align="center"
        type="index"
        :index="(index) => (currentPage - 1) * pageSize + index + 1"
      />
      <el-table-column
        prop="rule_id"
        label="规则 ID"
        width="120"
        show-overflow-tooltip
      />
      <el-table-column
        prop="name"
        label="规则名称"
        width="140"
        show-overflow-tooltip
      />
      <el-table-column prop="category" label="类别" width="90" align="center">
        <template #default="scope">
          <el-tag :type="getCategoryType(scope.row.category)" size="small">
            {{ scope.row.category }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column
        prop="priority"
        label="优先级"
        width="70"
        align="center"
        sortable
      >
        <template #default="scope">
          <el-tag :type="getPriorityType(scope.row.priority)" size="small">
            {{ scope.row.priority }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="protocol" label="协议" width="70" align="center" />
      <el-table-column label="匹配模式" width="200" show-overflow-tooltip>
        <template #default="scope">
          <div class="pattern-display">
            <el-tag
              :type="scope.row.pattern_type === 'pcre' ? 'warning' : 'success'"
              size="small"
              class="pattern-type-tag"
            >
              {{ scope.row.pattern_type === "pcre" ? "正则" : "字符串" }}
            </el-tag>
            <div class="pattern-content">
              <span class="pattern-text">{{
                getPatternPreview(scope.row.pattern)
              }}</span>
              <!-- 显示Per-Content选项数量 -->
              <el-tag
                v-if="scope.row.metadata && scope.row.metadata.content_options"
                type="info"
                size="mini"
                class="content-options-count"
              >
                {{ scope.row.metadata.content_options.length }} 个选项
              </el-tag>
            </div>
          </div>
        </template>
      </el-table-column>
      <el-table-column
        prop="tags"
        label="标签"
        width="100"
        show-overflow-tooltip
      >
        <template #default="scope">
          <el-tooltip
            v-if="scope.row.tags && scope.row.tags.length > 0"
            :content="scope.row.tags.join(', ')"
            placement="top"
          >
            <span class="tags-summary">
              {{ scope.row.tags.length }} 个标签
            </span>
          </el-tooltip>
          <span v-else class="no-tags">无标签</span>
        </template>
      </el-table-column>
      <el-table-column label="创建时间" width="140" sortable prop="created_at">
        <template #default="scope">
          <span class="created-time">
            {{ formatDate(scope.row.created_at) }}
          </span>
        </template>
      </el-table-column>
      <el-table-column
        prop="description"
        label="描述"
        width="120"
        show-overflow-tooltip
      />
      <el-table-column prop="enabled" label="状态" width="70" align="center">
        <template #default="scope">
          <el-switch
            v-model="scope.row.enabled"
            @change="toggleRule(scope.row)"
            size="small"
          />
        </template>
      </el-table-column>
      <el-table-column label="操作" width="140" align="center">
        <template #default="scope">
          <div class="action-buttons">
            <el-button type="primary" size="mini" @click="editRule(scope.row)">
              编辑
            </el-button>
            <el-button type="danger" size="mini" @click="deleteRule(scope.row)">
              删除
            </el-button>
          </div>
        </template>
      </el-table-column>
    </el-table>

    <!-- 分页 -->
    <div class="pagination-wrapper">
      <el-pagination
        v-model:current-page="currentPage"
        :page-size="pageSize"
        :total="totalRules"
        layout="total, prev, pager, next, jumper"
        @current-change="handleCurrentChange"
      />
    </div>

    <!-- 创建/编辑规则对话框 -->
    <el-dialog
      v-model="showCreateDialog"
      :title="isEditing ? '编辑规则' : '创建规则'"
      width="900px"
      :close-on-click-modal="false"
    >
      <div class="rule-format-info">
        <el-alert title="规则格式说明" type="info" :closable="false" show-icon>
          <template #description>
            <div class="format-description">
              <h4>📋 基本字段</h4>
              <ul>
                <li>
                  <strong>规则ID：</strong
                  >唯一标识符，只能包含字母、数字、下划线和连字符
                </li>
                <li><strong>规则名称：</strong>简要描述规则的作用</li>
                <li>
                  <strong>协议：</strong
                  >可选，TCP/UDP/ICMP/IP，留空表示匹配所有协议
                </li>
                <li><strong>优先级：</strong>1=高，2=中，3=低</li>
              </ul>

              <h4>🌐 网络匹配</h4>
              <ul>
                <li>
                  <strong>IP地址：</strong>支持 "any" 或具体IP，如 "192.168.1.1"
                </li>
                <li>
                  <strong>端口：</strong>支持 "any"、单个端口 "80" 或范围
                  "80:443"
                </li>
                <li>
                  <strong>方向：</strong>默认 "->" (单向)，可选 "<>" (双向)
                </li>
              </ul>

              <h4>🔍 内容匹配语法</h4>
              <div class="syntax-examples">
                <div class="syntax-group">
                  <h5>字符串匹配</h5>
                  <ul>
                    <li>
                      <strong>简单字符串：</strong><code>"GET /admin"</code> -
                      匹配HTTP GET请求到admin路径
                    </li>
                    <li>
                      <strong>包含特殊字符：</strong><code>"password: "</code> -
                      匹配密码提示
                    </li>
                    <li>
                      <strong>十六进制内容：</strong
                      ><code>"\x00\x01\x02data"</code> - 匹配包含null字节的数据
                    </li>
                  </ul>
                </div>

                <div class="syntax-group">
                  <h5>正则表达式 (PCRE)</h5>
                  <ul>
                    <li>
                      <strong>邮箱匹配：</strong
                      ><code
                        >"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"</code
                      >
                    </li>
                    <li>
                      <strong>IP地址：</strong
                      ><code>"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"</code>
                    </li>
                    <li>
                      <strong>SQL注入：</strong
                      ><code>"(?i)(union.*select|select.*from.*where)"</code>
                    </li>
                    <li>
                      <strong>路径遍历：</strong><code>"\.\./|\.\.\\"</code> -
                      匹配目录遍历攻击
                    </li>
                  </ul>
                </div>

                <div class="syntax-group">
                  <h5>匹配逻辑说明</h5>
                  <ul>
                    <li>
                      <strong>字符串模式：</strong
                      >直接字节匹配，支持二进制数据，性能高
                    </li>
                    <li>
                      <strong>正则模式：</strong
                      >灵活模式匹配，支持复杂逻辑，适用于文本协议
                    </li>
                    <li>
                      <strong>大小写：</strong
                      >字符串匹配区分大小写，正则表达式可使用(?i)忽略大小写
                    </li>
                    <li>
                      <strong>编码：</strong>自动处理UTF-8和Latin-1编码的payload
                    </li>
                  </ul>
                </div>

                <div class="syntax-group">
                  <h5>高级选项 (Snort兼容)</h5>
                  <ul>
                    <li>
                      <strong>offset：</strong>跳过前N字节，从第N+1字节开始搜索
                    </li>
                    <li>
                      <strong>depth：</strong
                      >从搜索起始位置开始，向后搜索的最大字节数
                    </li>
                    <li>
                      <strong>within：</strong>在offset之后，限制搜索的最大范围
                    </li>
                    <li>
                      <strong>distance：</strong>与上一个匹配的相对距离（字节）
                    </li>
                    <li>
                      <strong>nocase：</strong>不区分大小写匹配（仅字符串模式）
                    </li>
                    <li>
                      <strong>匹配位置选项：</strong>http_method, http_uri,
                      http_header, http_cookie, http_body, pkt_data -
                      指定内容匹配的位置
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </template>
        </el-alert>
      </div>

      <el-form
        ref="ruleFormRef"
        :model="ruleForm"
        :rules="ruleRules"
        label-width="120px"
      >
        <!-- 基本信息 -->
        <el-card class="form-section" shadow="never">
          <template #header>
            <div class="section-header">
              <el-icon><DocumentAdd /></el-icon>
              <span>基本信息</span>
            </div>
          </template>

          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item label="规则 ID" prop="rule_id">
                <el-input
                  v-model="ruleForm.rule_id"
                  :disabled="isEditing"
                  placeholder="唯一标识符，只能包含字母、数字、下划线和连字符"
                />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="规则名称" prop="name">
                <el-input
                  v-model="ruleForm.name"
                  placeholder="简要描述规则的作用"
                />
              </el-form-item>
            </el-col>
          </el-row>

          <el-row :gutter="20">
            <el-col :span="8">
              <el-form-item label="优先级" prop="priority">
                <el-select
                  v-model.number="ruleForm.priority"
                  placeholder="选择优先级"
                >
                  <el-option label="🔴 高" :value="1" />
                  <el-option label="🟡 中" :value="2" />
                  <el-option label="🟢 低" :value="3" />
                </el-select>
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item label="类别" prop="category">
                <el-input
                  v-model="ruleForm.category"
                  placeholder="输入规则类别"
                />
              </el-form-item>
            </el-col>
            <el-col :span="8">
              <el-form-item label="协议（可选）">
                <el-select
                  v-model="ruleForm.protocol"
                  clearable
                  placeholder="留空匹配所有协议"
                >
                  <el-option label="TCP" value="tcp" />
                  <el-option label="UDP" value="udp" />
                  <el-option label="ICMP" value="icmp" />
                  <el-option label="IP" value="ip" />
                </el-select>
              </el-form-item>
            </el-col>
          </el-row>

          <el-form-item label="描述">
            <el-input
              v-model="ruleForm.description"
              type="textarea"
              :rows="2"
              placeholder="详细描述规则的作用和触发条件"
            />
          </el-form-item>

          <el-form-item label="标签">
            <el-input
              v-model="ruleForm.tags_str"
              placeholder="用逗号分隔，如: web,sql-injection"
            >
              <template #suffix>
                <el-tooltip
                  content="用逗号分隔多个标签，如: web,sql-injection,dos。标签用于分类和搜索规则。"
                  placement="top"
                >
                  <el-icon class="info-icon"><InfoFilled /></el-icon>
                </el-tooltip>
              </template>
            </el-input>
          </el-form-item>

          <el-form-item label="启用状态">
            <el-switch v-model="ruleForm.enabled" />
            <span class="switch-hint">{{
              ruleForm.enabled ? "规则已启用" : "规则已禁用"
            }}</span>
          </el-form-item>
        </el-card>

        <!-- 网络匹配 -->
        <el-card class="form-section" shadow="never">
          <template #header>
            <div class="section-header">
              <el-icon><Monitor /></el-icon>
              <span>网络匹配条件</span>
            </div>
          </template>

          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item label="源 IP" prop="src">
                <el-input
                  v-model="ruleForm.src"
                  placeholder="如: any, 192.168.1.1, 192.168.0.0/16"
                />
                <template #suffix>
                  <el-tooltip
                    content="支持格式: any(任意), 单个IP, CIDR网段, !IP 表示取反"
                    placement="top"
                  >
                    <el-icon class="info-icon"><InfoFilled /></el-icon>
                  </el-tooltip>
                </template>
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="目标 IP" prop="dst">
                <el-input
                  v-model="ruleForm.dst"
                  placeholder="如: any, 192.168.1.1, 192.168.0.0/16"
                />
                <template #suffix>
                  <el-tooltip
                    content="支持格式: any(任意), 单个IP, CIDR网段, !IP 表示取反"
                    placement="top"
                  >
                    <el-icon class="info-icon"><InfoFilled /></el-icon>
                  </el-tooltip>
                </template>
              </el-form-item>
            </el-col>
          </el-row>

          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item label="源端口">
                <el-input
                  v-model="ruleForm.src_ports_str"
                  placeholder='支持: "any", "80", "80:443", "[80,443]", "!21"...'
                >
                  <template #suffix>
                    <el-tooltip
                      content='支持格式: "any"(任意), "80"(单个), "80:443"(范围), "[80,443]"(列表), "!21"(排除), "!21:23"(排除范围), "1024:"(开头范围), ":1023"(结尾范围)'
                      placement="top"
                    >
                      <el-icon class="info-icon"><InfoFilled /></el-icon>
                    </el-tooltip>
                  </template>
                </el-input>
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="目标端口">
                <el-input
                  v-model="ruleForm.dst_ports_str"
                  placeholder='支持: "any", "80", "80:443", "[80,443]", "!21"...'
                >
                  <template #suffix>
                    <el-tooltip
                      content='支持格式: "any"(任意), "80"(单个), "80:443"(范围), "[80,443]"(列表), "!21"(排除), "!21:23"(排除范围), "1024:"(开头范围), ":1023"(结尾范围)'
                      placement="top"
                    >
                      <el-icon class="info-icon"><InfoFilled /></el-icon>
                    </el-tooltip>
                  </template>
                </el-input>
              </el-form-item>
            </el-col>
          </el-row>
        </el-card>

        <!-- 内容匹配 -->
        <el-card class="form-section" shadow="never">
          <template #header>
            <div class="section-header">
              <el-icon><Search /></el-icon>
              <span>内容匹配条件</span>
            </div>
          </template>

          <el-alert
            title="内容匹配说明"
            description="支持多种匹配方式：字符串匹配、正则表达式、十六进制模式等。多个条件之间为AND关系。"
            type="info"
            :closable="false"
            class="content-match-alert"
          />

          <div
            v-for="(pattern, index) in ruleForm.patterns"
            :key="index"
            class="pattern-item"
          >
            <el-card class="pattern-card" shadow="hover">
              <template #header>
                <div class="pattern-header">
                  <span class="pattern-title">匹配条件 {{ index + 1 }}</span>
                  <el-button
                    type="danger"
                    size="small"
                    @click="removePattern(index)"
                    v-if="ruleForm.patterns.length > 1"
                  >
                    删除
                  </el-button>
                </div>
              </template>

              <el-row :gutter="20">
                <el-col :span="10">
                  <el-form-item label="匹配内容" class="pattern-form-item">
                    <el-input
                      v-model="pattern.content"
                      placeholder="支持混合格式，如: |00 01|Hello|02 03| 或纯文本"
                      :maxlength="2000"
                      show-word-limit
                    >
                      <template #suffix>
                        <el-tooltip
                          content="支持纯文本、十六进制(|00 01|)、二进制转义(\\x00)、混合格式。十六进制部分用|分隔，\\x用于单字节转义。"
                          placement="top"
                        >
                          <el-icon class="info-icon"><InfoFilled /></el-icon>
                        </el-tooltip>
                      </template>
                    </el-input>
                  </el-form-item>
                </el-col>
                <el-col :span="7">
                  <el-form-item label="匹配类型" class="pattern-form-item">
                    <el-select
                      v-model="pattern.match_type"
                      placeholder="选择匹配方式"
                    >
                      <el-option label="字符串匹配" value="string" />
                      <el-option label="正则表达式" value="regex" />
                    </el-select>
                  </el-form-item>
                </el-col>
                <el-col :span="7">
                  <el-form-item class="pattern-form-item">
                    <el-checkbox
                      v-model="pattern.nocase"
                      :disabled="pattern.match_type === 'regex'"
                    >
                      不区分大小写
                    </el-checkbox>
                  </el-form-item>
                </el-col>
              </el-row>

              <el-row :gutter="20">
                <el-col :span="8">
                  <el-form-item :label="`偏移量 ${index + 1}`">
                    <el-input
                      v-model="pattern.offset"
                      placeholder="如: 0"
                      type="number"
                    >
                      <template #suffix>
                        <el-tooltip
                          content="从数据包的第N+1字节开始搜索匹配内容。0表示从开始位置搜索。"
                          placement="top"
                        >
                          <el-icon class="info-icon"><InfoFilled /></el-icon>
                        </el-tooltip>
                      </template>
                    </el-input>
                  </el-form-item>
                </el-col>
                <el-col :span="8">
                  <el-form-item :label="`深度 ${index + 1}`">
                    <el-input
                      v-model="pattern.depth"
                      placeholder="如: 100"
                      type="number"
                    >
                      <template #suffix>
                        <el-tooltip
                          content="从偏移位置开始，向后搜索的最大字节数。留空表示搜索到数据包结尾。"
                          placement="top"
                        >
                          <el-icon class="info-icon"><InfoFilled /></el-icon>
                        </el-tooltip>
                      </template>
                    </el-input>
                  </el-form-item>
                </el-col>
                <el-col :span="8">
                  <el-form-item :label="`距离 ${index + 1}`">
                    <el-input
                      v-model="pattern.distance"
                      placeholder="如: 0"
                      type="number"
                    >
                      <template #suffix>
                        <el-tooltip
                          content="与上一个匹配内容之间的相对距离（字节数）。0表示紧接着上一个匹配。"
                          placement="top"
                        >
                          <el-icon class="info-icon"><InfoFilled /></el-icon>
                        </el-tooltip>
                      </template>
                    </el-input>
                  </el-form-item>
                </el-col>
              </el-row>

              <el-row :gutter="20">
                <el-col :span="12">
                  <el-form-item :label="`Within ${index + 1}`">
                    <el-input
                      v-model="pattern.within"
                      placeholder="如: 50"
                      type="number"
                    >
                      <template #suffix>
                        <el-tooltip
                          content="在偏移位置之后，限制搜索的最大范围（字节数）。用于精确控制匹配位置。"
                          placement="top"
                        >
                          <el-icon class="info-icon"><InfoFilled /></el-icon>
                        </el-tooltip>
                      </template>
                    </el-input>
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item :label="`匹配位置 ${index + 1}`">
                    <el-select
                      v-model="pattern.http_options"
                      multiple
                      placeholder="选择匹配位置"
                      collapse-tags
                    >
                      <el-option label="HTTP URI" value="http_uri" />
                      <el-option label="HTTP Method" value="http_method" />
                      <el-option label="HTTP Header" value="http_header" />
                      <el-option label="HTTP Cookie" value="http_cookie" />
                      <el-option label="HTTP Body" value="http_body" />
                      <el-option label="数据包数据" value="pkt_data" />
                    </el-select>
                  </el-form-item>
                </el-col>
              </el-row>
            </el-card>
          </div>

          <el-button type="primary" @click="addPattern" class="add-pattern-btn">
            <el-icon><Plus /></el-icon>
            添加匹配条件
          </el-button>
        </el-card>

        <!-- 高级选项 -->
        <el-card class="form-section" shadow="never">
          <template #header>
            <div class="section-header">
              <el-icon><Setting /></el-icon>
              <span>高级选项</span>
            </div>
          </template>

          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item label="TTL">
                <el-input
                  v-model="ruleForm.ttl"
                  placeholder="如: 128"
                  type="number"
                >
                  <template #suffix>
                    <el-tooltip
                      content="IP数据包的生存时间(TTL)值。用于匹配特定TTL值的数据包。"
                      placement="top"
                    >
                      <el-icon class="info-icon"><InfoFilled /></el-icon>
                    </el-tooltip>
                  </template>
                </el-input>
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="TOS">
                <el-input v-model="ruleForm.tos" placeholder="如: 0x00">
                  <template #suffix>
                    <el-tooltip
                      content="IP数据包的服务类型(TOS)字段。用于匹配特定的服务类型值。"
                      placement="top"
                    >
                      <el-icon class="info-icon"><InfoFilled /></el-icon>
                    </el-tooltip>
                  </template>
                </el-input>
              </el-form-item>
            </el-col>
          </el-row>

          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item label="ID">
                <el-input
                  v-model="ruleForm.ip_id"
                  placeholder="如: 12345"
                  type="number"
                >
                  <template #suffix>
                    <el-tooltip
                      content="IP数据包的标识符(ID)字段。用于匹配特定的IP数据包ID。"
                      placement="top"
                    >
                      <el-icon class="info-icon"><InfoFilled /></el-icon>
                    </el-tooltip>
                  </template>
                </el-input>
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="IP选项">
                <el-input v-model="ruleForm.ipopts" placeholder="如: rr">
                  <template #suffix>
                    <el-tooltip
                      content="IP数据包的选项字段。用于匹配特定的IP选项，如rr(记录路由)、ts(时间戳)等。"
                      placement="top"
                    >
                      <el-icon class="info-icon"><InfoFilled /></el-icon>
                    </el-tooltip>
                  </template>
                </el-input>
              </el-form-item>
            </el-col>
          </el-row>

          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item label="分片标志">
                <el-select
                  v-model="ruleForm.fragbits"
                  placeholder="分片标志"
                  clearable
                >
                  <el-option label="M (更多分片)" value="M" />
                  <el-option label="D (不分片)" value="D" />
                  <el-option label="R (保留位)" value="R" />
                </el-select>
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="分片偏移">
                <el-input
                  v-model="ruleForm.fragoffset"
                  placeholder="分片偏移值"
                  type="number"
                />
              </el-form-item>
            </el-col>
          </el-row>

          <el-form-item label="TCP标志">
            <el-input v-model="ruleForm.flags" placeholder="如: SA">
              <template #suffix>
                <el-tooltip
                  content="TCP数据包的标志位。用于匹配特定的TCP控制标志，如S(SYN)、A(ACK)、F(FIN)、R(RST)、P(PSH)、U(URG)等。可以组合使用，如SA表示SYN+ACK。"
                  placement="top"
                >
                  <el-icon class="info-icon"><InfoFilled /></el-icon>
                </el-tooltip>
              </template>
            </el-input>
          </el-form-item>

          <el-form-item label="序列号">
            <el-input
              v-model="ruleForm.seq"
              placeholder="如: 123456789"
              type="number"
            >
              <template #suffix>
                <el-tooltip
                  content="TCP数据包的序列号字段。用于匹配特定的TCP序列号。"
                  placement="top"
                >
                  <el-icon class="info-icon"><InfoFilled /></el-icon>
                </el-tooltip>
              </template>
            </el-input>
          </el-form-item>

          <el-form-item label="确认号">
            <el-input
              v-model="ruleForm.ack"
              placeholder="如: 987654321"
              type="number"
            >
              <template #suffix>
                <el-tooltip
                  content="TCP数据包的确认号字段。用于匹配特定的TCP确认号。"
                  placement="top"
                >
                  <el-icon class="info-icon"><InfoFilled /></el-icon>
                </el-tooltip>
              </template>
            </el-input>
          </el-form-item>

          <el-form-item label="窗口大小">
            <el-input
              v-model="ruleForm.window"
              placeholder="如: 65535"
              type="number"
            >
              <template #suffix>
                <el-tooltip
                  content="TCP数据包的窗口大小字段。用于匹配特定的TCP窗口大小。"
                  placement="top"
                >
                  <el-icon class="info-icon"><InfoFilled /></el-icon>
                </el-tooltip>
              </template>
            </el-input>
          </el-form-item>

          <el-form-item label="ICMP类型">
            <el-input
              v-model="ruleForm.icmp_type"
              placeholder="如: 8"
              type="number"
            >
              <template #suffix>
                <el-tooltip
                  content="ICMP数据包的类型字段。用于匹配特定的ICMP消息类型，如8表示回显请求。"
                  placement="top"
                >
                  <el-icon class="info-icon"><InfoFilled /></el-icon>
                </el-tooltip>
              </template>
            </el-input>
          </el-form-item>

          <el-form-item label="ICMP代码">
            <el-input
              v-model="ruleForm.icmp_code"
              placeholder="如: 0"
              type="number"
            >
              <template #suffix>
                <el-tooltip
                  content="ICMP数据包的代码字段。用于进一步指定ICMP消息的子类型。"
                  placement="top"
                >
                  <el-icon class="info-icon"><InfoFilled /></el-icon>
                </el-tooltip>
              </template>
            </el-input>
          </el-form-item>
        </el-card>
      </el-form>
      <template #footer>
        <div class="dialog-footer-actions">
          <el-button
            @click="isEditing ? cancelEdit() : (showCreateDialog = false)"
          >
            取消
          </el-button>
          <el-button
            type="primary"
            @click="submitForm"
            :loading="submitLoading"
          >
            {{ isEditing ? "更新规则" : "创建规则" }}
          </el-button>
          <el-button @click="resetForm">重置</el-button>
        </div>
      </template>
    </el-dialog>

    <!-- 导入规则对话框 -->
    <el-dialog
      v-model="showImportDialog"
      title="导入规则"
      width="700px"
      :close-on-click-modal="false"
    >
      <el-tabs v-model="importTab" @tab-click="handleImportTabClick">
        <el-tab-pane label="Snort 规则文件" name="snort">
          <div class="import-section">
            <el-alert
              title="Snort 规则格式支持"
              type="success"
              :closable="false"
              show-icon
              style="margin-bottom: 16px"
            >
              <template #description>
                <div class="snort-format-info">
                  <p><strong>✅ 支持的Snort语法：</strong></p>
                  <div class="snort-examples">
                    <div class="snort-group">
                      <h5>基本规则格式</h5>
                      <code
                        >alert tcp any any -> any 80 (msg:"HTTP GET";
                        content:"GET"; sid:1001;)</code
                      >
                      <p>
                        action protocol src_ip src_port -> dst_ip dst_port
                        (options)
                      </p>
                    </div>

                    <div class="snort-group">
                      <h5>内容匹配选项</h5>
                      <ul>
                        <li><code>content:"字符串";</code> - 纯文本匹配</li>
                        <li>
                          <code>content:|十六进制|;</code> - 纯十六进制，如 |00
                          01 02|
                        </li>
                        <li>
                          <code>content:"text|hex|text";</code> - 混合格式
                        </li>
                        <li>
                          <code>pcre:"/正则表达式/";</code> - 正则表达式匹配
                        </li>
                      </ul>
                    </div>

                    <div class="snort-group">
                      <h5>端口和地址</h5>
                      <ul>
                        <li><code>any</code> - 匹配任何端口/IP</li>
                        <li><code>80</code> - 单个端口</li>
                        <li><code>80:443</code> - 端口范围（包含80到443）</li>
                        <li><code>[80,443,8080]</code> - 端口列表</li>
                        <li>
                          <code>!21</code> -
                          否定单个端口（除了21端口外的所有端口）
                        </li>
                        <li>
                          <code>!21:23</code> -
                          否定端口范围（除了21-23外的所有端口）
                        </li>
                        <li>
                          <code>1024:</code> - 开头范围（1024及以上的所有端口）
                        </li>
                        <li>
                          <code>:1023</code> - 结尾范围（1023及以下的所有端口）
                        </li>
                        <li><code>192.168.1.0/24</code> - CIDR地址范围</li>
                        <li>
                          <code>!192.168.1.0/24</code> -
                          否定CIDR（不在此范围内）
                        </li>
                        <li>
                          <code>$HOME_NET</code> - Snort变量（导入时自动解析）
                        </li>
                        <li>
                          <code>!$HOME_NET</code> -
                          否定Snort变量（不在变量范围内）
                        </li>
                      </ul>
                    </div>

                    <div class="snort-group">
                      <h5>HTTP流量选项</h5>
                      <ul>
                        <li>
                          <code>uricontent:"字符串";</code> - HTTP URI内容匹配
                        </li>
                        <li>
                          <code>http_stat_code:状态码;</code> -
                          HTTP响应状态码匹配
                        </li>
                        <li>
                          <code>http_method;</code> -
                          HTTP方法匹配（需配合content使用）
                        </li>
                        <li><code>http_header;</code> - HTTP头部匹配</li>
                        <li><code>http_cookie;</code> - HTTP Cookie匹配</li>
                        <li><code>http_body;</code> - HTTP请求体匹配</li>
                      </ul>
                    </div>

                    <div class="snort-group">
                      <h5>常用选项</h5>
                      <ul>
                        <li><code>msg:"描述";</code> - 规则描述</li>
                        <li><code>sid:数字;</code> - 规则ID</li>
                        <li><code>classtype:类型;</code> - 攻击分类</li>
                        <li><code>flow:方向;</code> - 会话方向</li>
                        <li><code>depth:数字;</code> - 匹配深度</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </template>
            </el-alert>

            <p>上传 Snort 格式的规则文件 (.rules)</p>
            <el-upload
              ref="snortUploadRef"
              class="upload-demo"
              drag
              :action="`${apiBase}/api/rules/bulk-import`"
              :headers="uploadHeaders"
              :on-success="handleSnortImportSuccess"
              :on-error="handleImportError"
              :before-upload="beforeSnortUpload"
              accept=".rules"
              :show-file-list="false"
            >
              <el-icon class="el-icon--upload"><UploadFilled /></el-icon>
              <div class="el-upload__text">
                将文件拖到此处，或 <em>点击上传</em>
              </div>
              <template #tip>
                <div class="el-upload__tip">
                  只能上传 .rules 文件，且不超过 10MB
                </div>
              </template>
            </el-upload>
          </div>
        </el-tab-pane>

        <el-tab-pane label="JSON 规则" name="json">
          <div class="import-section">
            <p>粘贴 JSON 格式的规则列表</p>
            <el-input
              v-model="jsonRulesText"
              type="textarea"
              :rows="10"
              placeholder='[{"name": "规则名称", "patterns": ["匹配内容"], "severity": "high", "description": "描述"}]'
            />
            <el-button
              type="primary"
              @click="importJsonRules"
              :loading="importing"
              style="margin-top: 10px"
            >
              导入 JSON 规则
            </el-button>
          </div>
        </el-tab-pane>

        <el-tab-pane label="Snort变量配置" name="variables">
          <div class="import-section">
            <el-alert
              title="Snort变量说明"
              type="info"
              :closable="false"
              show-icon
              style="margin-bottom: 16px"
            >
              <template #description>
                Snort规则中的变量（如$HOME_NET）需要配置为实际的IP地址范围。
                默认值只是示例，请根据您的网络环境进行调整。
              </template>
            </el-alert>

            <div v-loading="loadingVariables" class="variables-grid">
              <el-row
                :gutter="20"
                v-for="(variable, index) in snortVariables"
                :key="variable.name"
              >
                <el-col :span="8">
                  <strong>{{ variable.name }}</strong>
                  <div class="variable-description">
                    {{ variable.description }}
                  </div>
                </el-col>
                <el-col :span="12">
                  <el-input
                    v-model="variable.value"
                    :placeholder="variable.example"
                    @blur="updateVariable(variable.name, variable.value)"
                  />
                </el-col>
                <el-col :span="4">
                  <el-button
                    type="primary"
                    size="small"
                    @click="updateVariable(variable.name, variable.value)"
                  >
                    更新
                  </el-button>
                </el-col>
              </el-row>
            </div>

            <el-button
              type="success"
              @click="loadSnortVariables"
              style="margin-top: 20px"
            >
              <el-icon><Refresh /></el-icon>
              刷新配置
            </el-button>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-dialog>
  </div>
</template>

<script>
import { ref, reactive, onMounted, computed, watch, nextTick } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  DocumentAdd,
  Plus,
  Upload,
  Search,
  Monitor,
  Setting,
  Management,
  Delete,
  Check,
  InfoFilled,
} from "@element-plus/icons-vue";

export default {
  setup() {
    const rules = ref([]);
    const loading = ref(false);
    const submitting = ref(false);
    const submitLoading = computed(() => submitting.value);
    const importing = ref(false);

    const showCreateDialog = ref(false);
    const showImportDialog = ref(false);
    const isEditing = ref(false);
    const importTab = ref("snort");
    const advancedOptionsActive = ref([]); // 折叠面板状态

    const currentPage = ref(1);
    const pageSize = ref(20);
    const totalRules = ref(0);

    // 搜索和筛选
    const searchText = ref("");
    const filterCategory = ref("");
    const filterTags = ref("");

    const apiBase = ""; // 相对路径，由代理处理

    // 计算属性：过滤后的规则列表
    const filteredRules = computed(() => {
      let filtered = rules.value;

      // 按类别筛选
      if (filterCategory.value && filterCategory.value.trim()) {
        const categoryTerm = filterCategory.value.toLowerCase().trim();
        filtered = filtered.filter(
          (rule) =>
            rule.category && rule.category.toLowerCase().includes(categoryTerm),
        );
      }

      // 按标签筛选
      if (filterTags.value && filterTags.value.trim()) {
        const tagTerm = filterTags.value.toLowerCase().trim();
        filtered = filtered.filter(
          (rule) =>
            rule.tags &&
            rule.tags.some((tag) => tag.toLowerCase().includes(tagTerm)),
        );
      }

      // 按搜索文本筛选
      if (searchText.value.trim()) {
        const searchTerm = searchText.value.toLowerCase().trim();
        filtered = filtered.filter(
          (rule) =>
            rule.rule_id.toLowerCase().includes(searchTerm) ||
            rule.name.toLowerCase().includes(searchTerm) ||
            (rule.description &&
              rule.description.toLowerCase().includes(searchTerm)),
        );
      }

      return filtered;
    });

    const ruleForm = reactive({
      rule_id: "",
      name: "",
      protocol: null,
      priority: 2,
      category: "custom",
      src: "any",
      dst: "any",
      src_ports_str: "any",
      dst_ports_str: "any",
      description: "",
      tags_str: "",
      enabled: true,
      // 内容匹配
      patterns: [
        {
          content: "",
          match_type: "string",
          nocase: false,
          offset: null,
          depth: null,
          distance: null,
          within: null,
          http_options: [],
        },
      ],
      // 高级选项
      ttl: null,
      tos: null,
      ip_id: null,
      ipopts: null,
      fragbits: null,
      fragoffset: null,
      flags: null,
      seq: null,
      ack: null,
      window: null,
      icmp_type: null,
      icmp_code: null,
    });

    const ruleFormRef = ref(null);
    const snortUploadRef = ref(null);
    const jsonRulesText = ref("");
    const rulesTableRef = ref(null);
    const selectedRules = ref([]);
    const batchDeleting = ref(false);
    const selectAllMode = ref(false); // 是否处于全选模式
    const allSelectedRuleIds = ref([]); // 所有选中的规则ID（包括不在当前页的）
    const excludedRules = ref([]); // 在全选模式下被取消勾选的规则ID

    // Snort变量配置
    const snortVariables = ref([]);
    const loadingVariables = ref(false);

    const ruleRules = {
      rule_id: [
        { required: true, message: "请输入规则 ID", trigger: "blur" },
        {
          pattern: /^[a-zA-Z0-9_-]+$/,
          message: "规则 ID 只能包含字母、数字、下划线和连字符",
          trigger: "blur",
        },
      ],
      name: [{ required: true, message: "请输入规则名称", trigger: "blur" }],
      priority: [
        { required: true, message: "请选择优先级", trigger: "change" },
      ],
      category: [
        { required: true, message: "请选择规则类别", trigger: "change" },
      ],
      src: [{ required: true, message: "请输入源IP", trigger: "blur" }],
      dst: [{ required: true, message: "请输入目标IP", trigger: "blur" }],
    };

    const patternRules = {
      content: [{ required: true, message: "请输入匹配内容", trigger: "blur" }],
    };

    const uploadHeaders = computed(() => ({
      // 如果需要认证，可以在这里添加
    }));

    // 计算要删除的规则数量
    const rulesToDeleteCount = computed(() => {
      if (selectAllMode.value) {
        // 全选模式：所有规则数量减去排除的规则数量
        return allSelectedRuleIds.value.length - excludedRules.value.length;
      } else {
        // 普通模式：选中的规则数量
        return selectedRules.value.length;
      }
    });

    const getCategoryType = (category) => {
      const types = {
        web: "danger",
        admin: "warning",
        dos: "danger",
        recon: "info",
        policy: "success",
        custom: "",
      };
      return types[category] || "";
    };

    const getPriorityType = (priority) => {
      const types = {
        1: "danger",
        2: "warning",
        3: "info",
      };
      return types[priority] || "info";
    };

    const getPatternPreview = (pattern) => {
      if (!pattern) return "";
      if (typeof pattern === "string") {
        // 处理Snort格式的十六进制内容 (如 "text|hex bytes|more text")
        if (pattern.includes("|")) {
          const parts = pattern.split("|");
          let result = "";
          for (let i = 0; i < parts.length; i++) {
            if (i % 2 === 0) {
              // 字符串部分
              result += parts[i];
            } else {
              // 十六进制部分 - 显示为可读格式
              const hexStr = parts[i].replace(/\s+/g, "");
              if (hexStr) {
                try {
                  const bytes = [];
                  for (let j = 0; j < hexStr.length; j += 2) {
                    bytes.push(parseInt(hexStr.substr(j, 2), 16));
                  }
                  // 显示为十六进制转义格式
                  result += bytes
                    .map((b) => {
                      if (b >= 32 && b <= 126) {
                        return String.fromCharCode(b);
                      } else {
                        return `\\x${b.toString(16).padStart(2, "0")}`;
                      }
                    })
                    .join("");
                } catch (e) {
                  result += `[${parts[i]}]`;
                }
              }
            }
          }
          return result.length > 50 ? result.substring(0, 50) + "..." : result;
        }

        // 如果包含null字节，显示为十六进制预览
        if (pattern.includes("\x00")) {
          return (
            pattern
              .replace(/[\x00-\x1F\x7F-\x9F]/g, (char) => {
                return `\\x${char.charCodeAt(0).toString(16).padStart(2, "0")}`;
              })
              .substring(0, 50) + (pattern.length > 50 ? "..." : "")
          );
        }
        return pattern.length > 50 ? pattern.substring(0, 50) + "..." : pattern;
      }
      if (Array.isArray(pattern)) {
        return pattern.length > 1
          ? `${pattern[0]} (+${pattern.length - 1} more)`
          : pattern[0] || "";
      }
      return String(pattern);
    };

    const formatDate = (dateString) => {
      if (!dateString) return "";
      const date = new Date(dateString);
      return date.toLocaleString("zh-CN", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      });
    };

    const loadRules = async () => {
      loading.value = true;
      try {
        const skip = (currentPage.value - 1) * pageSize.value;
        const params = new URLSearchParams({
          skip: skip.toString(),
          limit: pageSize.value.toString(),
          search: searchText.value,
          category: filterCategory.value,
          tags: filterTags.value,
        });
        const response = await fetch(`${apiBase}/api/rules/?${params}`);
        if (response.ok) {
          const data = await response.json();
          rules.value = data.rules;
          totalRules.value = data.total;

          // 如果是全选模式，默认所有规则都被选中，除非在排除列表中
          if (selectAllMode.value) {
            nextTick(() => {
              rules.value.forEach((rule) => {
                const shouldSelect = !excludedRules.value.includes(
                  rule.rule_id,
                );
                rulesTableRef.value?.toggleRowSelection(rule, shouldSelect);
              });
              // 更新selectedRules
              selectedRules.value = rules.value.filter(
                (rule) => !excludedRules.value.includes(rule.rule_id),
              );
            });
          }
        } else {
          ElMessage.error("加载规则失败");
        }
      } catch (error) {
        console.error("加载规则失败:", error);
        ElMessage.error("加载规则失败");
      } finally {
        loading.value = false;
      }
    };

    const toggleRule = async (rule) => {
      try {
        const response = await fetch(`${apiBase}/api/rules/${rule.rule_id}`, {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(rule),
        });

        if (!response.ok) {
          // 恢复开关状态
          rule.enabled = !rule.enabled;
          ElMessage.error("更新规则状态失败");
        } else {
          ElMessage.success("规则状态已更新");
        }
      } catch (error) {
        // 恢复开关状态
        rule.enabled = !rule.enabled;
        console.error("更新规则状态失败:", error);
        ElMessage.error("更新规则状态失败");
      }
    };

    const editRule = (rule) => {
      // 复制规则数据到表单
      const metadata = rule.metadata || {};
      Object.assign(ruleForm, {
        rule_id: rule.rule_id,
        name: rule.name,
        protocol: rule.protocol,
        priority: rule.priority,
        category: rule.category,
        src: rule.src,
        dst: rule.dst,
        src_ports_str: rule.src_ports ? rule.src_ports.join(",") : "any",
        dst_ports_str: rule.dst_ports ? rule.dst_ports.join(",") : "any",
        description: rule.description,
        tags_str: rule.tags ? rule.tags.join(",") : "",
        enabled: rule.enabled,
        // 高级选项
        ttl: metadata.ttl || null,
        tos: metadata.tos || null,
        ip_id: metadata.ip_id || null,
        ipopts: metadata.ipopts || null,
        fragbits: metadata.fragbits || null,
        fragoffset: metadata.fragoffset || null,
        flags: metadata.flags || null,
        seq: metadata.seq || null,
        ack: metadata.ack || null,
        window: metadata.window || null,
        icmp_type: metadata.icmp_type || null,
        icmp_code: metadata.icmp_code || null,
      });

      // 处理patterns
      if (rule.pattern && Array.isArray(rule.pattern)) {
        ruleForm.patterns = rule.pattern.map((content, index) => {
          const contentOptions =
            metadata.content_options && metadata.content_options[index];
          return {
            content: content,
            match_type: rule.pattern_type === "pcre" ? "regex" : "string",
            nocase: contentOptions?.nocase || false,
            offset: contentOptions?.offset || null,
            depth: contentOptions?.depth || null,
            distance: contentOptions?.distance || null,
            within: contentOptions?.within || null,
            http_options: [],
          };
        });
      } else if (rule.pattern) {
        ruleForm.patterns = [
          {
            content: rule.pattern,
            match_type: rule.pattern_type === "pcre" ? "regex" : "string",
            nocase: metadata.nocase || false,
            offset: metadata.offset || null,
            depth: metadata.depth || null,
            distance: metadata.distance || null,
            within: metadata.within || null,
            http_options: [],
          },
        ];
      } else {
        ruleForm.patterns = [
          {
            content: "",
            match_type: "string",
            offset: null,
            depth: null,
            distance: null,
            within: null,
            http_options: [],
          },
        ];
      }

      isEditing.value = true;
      showCreateDialog.value = true;
    };

    const deleteRule = async (rule) => {
      try {
        await ElMessageBox.confirm(
          `确定要删除规则 "${rule.name}" 吗？此操作不可恢复。`,
          "确认删除",
          {
            confirmButtonText: "确定",
            cancelButtonText: "取消",
            type: "warning",
          },
        );

        const response = await fetch(`${apiBase}/api/rules/${rule.rule_id}`, {
          method: "DELETE",
        });

        if (response.ok) {
          ElMessage.success("规则已删除");
          loadRules();
        } else {
          ElMessage.error("删除规则失败");
        }
      } catch (error) {
        if (error !== "cancel") {
          console.error("删除规则失败:", error);
          ElMessage.error("删除规则失败");
        }
      }
    };

    // 选择变化处理
    const handleSelectionChange = (selection) => {
      if (!selectAllMode.value) {
        selectedRules.value = selection;
      } else {
        // 在全选模式下，维护排除列表
        selectedRules.value = selection;
        // 更新排除列表：当前页面中未被选中的规则ID
        const currentPageRuleIds = rules.value.map((rule) => rule.rule_id);
        const selectedIds = selection.map((rule) => rule.rule_id);
        const pageExcluded = currentPageRuleIds.filter(
          (id) => !selectedIds.includes(id),
        );

        // 从全局排除列表中移除当前页面被选中的规则，添加当前页面未被选中的规则
        excludedRules.value = excludedRules.value.filter(
          (id) => !currentPageRuleIds.includes(id),
        );
        excludedRules.value.push(...pageExcluded);
      }
    };

    // 全选全部规则
    const selectAllRules = async () => {
      try {
        const params = new URLSearchParams({
          search: searchText.value,
          category: filterCategory.value,
          tags: filterTags.value,
        });
        const response = await fetch(`${apiBase}/api/rules/ids?${params}`);
        if (response.ok) {
          const allIds = await response.json();
          allSelectedRuleIds.value = allIds;
          selectAllMode.value = true;
          excludedRules.value = []; // 重置排除列表

          // 在全选模式下，所有规则都被选中（要删除），用户可以取消勾选要保留的规则
          selectedRules.value = [...rules.value]; // 当前页面的规则

          // 选中当前页面的所有规则
          rules.value.forEach((rule) => {
            rulesTableRef.value?.toggleRowSelection(rule, true);
          });
        }
      } catch (error) {
        console.error("全选规则失败:", error);
        ElMessage.error("全选规则失败");
      }
    };

    // 取消选择
    const clearSelection = () => {
      rulesTableRef.value?.clearSelection();
      selectedRules.value = [];
      selectAllMode.value = false;
      allSelectedRuleIds.value = [];
      excludedRules.value = [];
    };

    // 批量删除规则
    const batchDeleteRules = async () => {
      let ruleIdsToDelete = [];

      if (selectAllMode.value) {
        // 在全选模式下，重新获取最新的规则ID列表，以防有规则被删除
        try {
          const params = new URLSearchParams({
            search: searchText.value,
            category: filterCategory.value,
            tags: filterTags.value,
          });
          const response = await fetch(`${apiBase}/api/rules/ids?${params}`);
          if (response.ok) {
            const freshIds = await response.json();
            allSelectedRuleIds.value = freshIds;
          }
        } catch (error) {
          console.error("重新获取规则ID失败:", error);
        }

        // 全选模式：删除所有规则，除了排除列表中的规则
        ruleIdsToDelete = allSelectedRuleIds.value.filter(
          (id) =>
            id &&
            typeof id === "string" &&
            id.trim().length > 0 &&
            !excludedRules.value.includes(id),
        );
      } else {
        // 普通模式：删除选中的规则
        ruleIdsToDelete = selectedRules.value.map((rule) => rule.rule_id);
      }

      // 过滤掉空值和无效ID
      ruleIdsToDelete = ruleIdsToDelete.filter(
        (id) => id && typeof id === "string" && id.trim().length > 0,
      );

      if (ruleIdsToDelete.length === 0) {
        ElMessage.warning("没有规则需要删除");
        return;
      }

      try {
        await ElMessageBox.confirm(
          `确定要删除 ${ruleIdsToDelete.length} 条规则吗？此操作不可恢复。`,
          "确认删除",
          {
            confirmButtonText: "确定删除",
            cancelButtonText: "取消",
            type: "warning",
          },
        );

        batchDeleting.value = true;

        const response = await fetch(`${apiBase}/api/rules/batch`, {
          method: "DELETE",
          headers: {
            "Content-Type": "application/json",
            ...uploadHeaders.value,
          },
          body: JSON.stringify(ruleIdsToDelete),
        });

        if (response.ok) {
          const result = await response.json();
          ElMessage.success(result.message);
          loadRules();
          clearSelection();
        } else {
          const error = await response.json();
          console.error("批量删除失败:", error);
          console.error("要删除的规则ID:", ruleIdsToDelete);
          ElMessage.error(error.detail || "批量删除失败");
        }
      } catch (error) {
        if (error !== "cancel") {
          console.error("批量删除规则失败:", error);
          ElMessage.error("批量删除规则失败");
        }
      } finally {
        batchDeleting.value = false;
      }
    };

    const submitRule = async () => {
      if (!ruleFormRef.value) return;

      await ruleFormRef.value.validate(async (valid) => {
        if (!valid) return;

        submitting.value = true;

        try {
          // 转换表单数据
          const ruleData = {
            rule_id: ruleForm.rule_id,
            name: ruleForm.name,
            action: "alert",
            protocol: ruleForm.protocol,
            priority: ruleForm.priority,
            category: ruleForm.category,
            src: ruleForm.src,
            dst: ruleForm.dst,
            src_ports:
              ruleForm.src_ports_str === "any"
                ? null
                : parsePorts(ruleForm.src_ports_str),
            dst_ports:
              ruleForm.dst_ports_str === "any"
                ? null
                : parsePorts(ruleForm.dst_ports_str),
            direction: "->",
            pattern: ruleForm.patterns
              .map((p) => p.content)
              .filter((content) => content && content.trim()),
            pattern_type:
              ruleForm.patterns[0]?.match_type === "regex" ? "pcre" : "string",
            description: ruleForm.description,
            tags: ruleForm.tags_str
              ? ruleForm.tags_str.split(",").map((t) => t.trim())
              : [],
            metadata: {
              // 高级选项
              ttl: ruleForm.ttl,
              tos: ruleForm.tos,
              ip_id: ruleForm.ip_id,
              ipopts: ruleForm.ipopts,
              fragbits: ruleForm.fragbits,
              fragoffset: ruleForm.fragoffset,
              flags: ruleForm.flags,
              seq: ruleForm.seq,
              ack: ruleForm.ack,
              window: ruleForm.window,
              icmp_type: ruleForm.icmp_type,
              icmp_code: ruleForm.icmp_code,
              // Per-content选项
              content_options: ruleForm.patterns.map((pattern) => ({
                offset: pattern.offset,
                depth: pattern.depth,
                distance: pattern.distance,
                within: pattern.within,
                nocase: pattern.nocase,
                http_method: pattern.http_options.includes("http_method"),
                http_uri: pattern.http_options.includes("http_uri"),
                http_header: pattern.http_options.includes("http_header"),
                http_cookie: pattern.http_options.includes("http_cookie"),
                http_body: pattern.http_options.includes("http_body"),
                pkt_data: pattern.http_options.includes("pkt_data"),
              })),
            },
            enabled: ruleForm.enabled,
          };

          const url = isEditing.value
            ? `${apiBase}/api/rules/${ruleForm.rule_id}`
            : `${apiBase}/api/rules/`;

          const method = isEditing.value ? "PUT" : "POST";

          const response = await fetch(url, {
            method,
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify(ruleData),
          });

          if (response.ok) {
            ElMessage.success(isEditing.value ? "规则已更新" : "规则已创建");
            showCreateDialog.value = false;
            loadRules();
            resetForm();
          } else {
            const error = await response.json();
            ElMessage.error(error.detail || "操作失败");
          }
        } catch (error) {
          console.error("提交规则失败:", error);
          ElMessage.error("操作失败");
        } finally {
          submitting.value = false;
        }
      });
    };

    const getPatternList = () => {
      if (!ruleForm.patterns || ruleForm.patterns.length === 0) {
        return [];
      }
      return ruleForm.patterns
        .map((p) => p.content)
        .filter((content) => content && content.trim());
    };

    const addPattern = () => {
      ruleForm.patterns.push({
        content: "",
        match_type: "string",
        nocase: false,
        offset: null,
        depth: null,
        distance: null,
        within: null,
        http_options: [],
      });
    };

    const removePattern = (index) => {
      if (ruleForm.patterns.length > 1) {
        ruleForm.patterns.splice(index, 1);
      }
    };

    // 初始化content_options
    const initContentOptions = () => {
      if (ruleForm.pattern_type === "string" && ruleForm.pattern) {
        const patterns = getPatternList();
        if (patterns.length !== ruleForm.content_options.length) {
          ruleForm.content_options = patterns.map(() => ({
            distance: null,
            offset: null,
            depth: null,
            within: null,
            match_location: "pkt_data",
            nocase: false,
          }));
        }
      } else {
        ruleForm.content_options = [];
      }
    };

    // 监听pattern变化，初始化content_options
    watch(
      () => ruleForm.pattern,
      (newPattern) => {
        initContentOptions();
      },
    );

    // 监听pattern_type变化
    watch(
      () => ruleForm.pattern_type,
      (newType) => {
        initContentOptions();
      },
    );

    const submitForm = () => {
      submitRule();
    };

    const cancelEdit = () => {
      showCreateDialog.value = false;
      resetForm();
    };

    const resetForm = () => {
      Object.assign(ruleForm, {
        rule_id: "",
        name: "",
        protocol: null,
        priority: 2,
        category: "custom",
        src: "any",
        dst: "any",
        src_ports_str: "any",
        dst_ports_str: "any",
        description: "",
        tags_str: "",
        enabled: true,
        // 重置内容匹配
        patterns: [
          {
            content: "",
            match_type: "string",
            nocase: false,
            offset: null,
            depth: null,
            distance: null,
            within: null,
            http_options: [],
          },
        ],
        // 重置高级选项
        ttl: null,
        tos: null,
        ip_id: null,
        ipopts: null,
        fragbits: null,
        fragoffset: null,
        flags: null,
        seq: null,
        ack: null,
        window: null,
        icmp_type: null,
        icmp_code: null,
      });
      isEditing.value = false;
      if (ruleFormRef.value) {
        ruleFormRef.value.clearValidate();
      }
    };

    const handleCreateRule = () => {
      resetForm();
      showCreateDialog.value = true;
    };

    const handleSnortImportSuccess = (response) => {
      if (response.message) {
        // 显示导入结果摘要
        if (response.failed > 0) {
          ElMessage.warning(`${response.message}。查看控制台获取失败详情。`);
          // 在控制台显示失败的规则详情
          console.group("🚫 Snort规则导入失败详情");
          console.log(`总规则数: ${response.total}`);
          console.log(`成功导入: ${response.imported}`);
          console.log(`导入失败: ${response.failed}`);
          console.log("失败规则列表:");
          response.failed_rules.forEach((failed, index) => {
            console.log(`${index + 1}. 第${failed.line}行: ${failed.error}`);
            console.log(`   规则: ${failed.rule}`);
          });
          console.groupEnd();
        } else {
          ElMessage.success(response.message);
        }

        showImportDialog.value = false;
        loadRules();
      }
    };

    const handleImportError = (error) => {
      console.error("导入失败:", error);
      ElMessage.error("导入失败，请检查文件格式");
    };

    const beforeSnortUpload = (file) => {
      const isRules =
        file.type === "text/plain" || file.name.endsWith(".rules");
      const isLt10M = file.size / 1024 / 1024 < 10;

      if (!isRules) {
        ElMessage.error("只能上传 .rules 格式的文件!");
        return false;
      }
      if (!isLt10M) {
        ElMessage.error("上传文件大小不能超过 10MB!");
        return false;
      }
      return true;
    };

    const importJsonRules = async () => {
      if (!jsonRulesText.value.trim()) {
        ElMessage.warning("请输入 JSON 规则数据");
        return;
      }

      try {
        const rulesData = JSON.parse(jsonRulesText.value);
        if (!Array.isArray(rulesData)) {
          ElMessage.error("JSON 数据必须是数组格式");
          return;
        }

        importing.value = true;

        const response = await fetch(`${apiBase}/api/rules/bulk-import-json`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(rulesData),
        });

        if (response.ok) {
          const result = await response.json();
          ElMessage.success(result.message);
          showImportDialog.value = false;
          jsonRulesText.value = "";
          loadRules();
        } else {
          const error = await response.json();
          ElMessage.error(error.detail || "导入失败");
        }
      } catch (error) {
        console.error("JSON 解析或导入失败:", error);
        ElMessage.error("JSON 格式错误或导入失败");
      } finally {
        importing.value = false;
      }
    };

    const handleImportTabClick = (tab) => {
      // 切换标签时的处理
      if (tab.props.name === "variables") {
        loadSnortVariables();
      }
    };

    // Snort变量配置相关方法
    const loadSnortVariables = async () => {
      loadingVariables.value = true;
      try {
        const response = await fetch(`${apiBase}/api/rules/snort-variables`);
        if (response.ok) {
          const data = await response.json();
          snortVariables.value = Object.entries(data).map(([name, value]) => ({
            name,
            value,
            description: getVariableDescription(name),
            example: getVariableExample(name),
          }));
        } else {
          ElMessage.error("加载Snort变量配置失败");
        }
      } catch (error) {
        console.error("加载Snort变量配置失败:", error);
        ElMessage.error("加载Snort变量配置失败");
      } finally {
        loadingVariables.value = false;
      }
    };

    const updateVariable = async (varName, varValue) => {
      if (!varValue.trim()) {
        ElMessage.warning("变量值不能为空");
        return;
      }

      try {
        const response = await fetch(
          `${apiBase}/api/rules/snort-variables/${varName}?value=${encodeURIComponent(varValue)}`,
          {
            method: "PUT",
          },
        );

        if (response.ok) {
          ElMessage.success(`变量 ${varName} 已更新`);
        } else {
          const error = await response.json();
          ElMessage.error(error.detail || "更新变量失败");
        }
      } catch (error) {
        console.error("更新变量失败:", error);
        ElMessage.error("更新变量失败");
      }
    };

    const getVariableDescription = (name) => {
      const descriptions = {
        HOME_NET: "内部网络地址范围",
        EXTERNAL_NET: "外部网络地址范围",
        HTTP_SERVERS: "HTTP服务器地址",
        SMTP_SERVERS: "SMTP服务器地址",
        SQL_SERVERS: "SQL服务器地址",
        DNS_SERVERS: "DNS服务器地址",
        TELNET_SERVERS: "Telnet服务器地址",
        SNMP_SERVERS: "SNMP服务器地址",
        FTP_SERVERS: "FTP服务器地址",
        SSH_SERVERS: "SSH服务器地址",
        SIP_SERVERS: "SIP服务器地址",
        HTTP_PORTS: "HTTP端口",
        SHELLCODE_PORTS: "Shellcode端口",
        ORACLE_PORTS: "Oracle端口",
        SSH_PORTS: "SSH端口",
        FTP_PORTS: "FTP端口",
        SIP_PORTS: "SIP端口",
        FILE_DATA_PORTS: "文件数据端口",
        GTP_PORTS: "GTP端口",
      };
      return descriptions[name] || "自定义变量";
    };

    const getVariableExample = (name) => {
      const examples = {
        HOME_NET: "192.168.0.0/16,10.0.0.0/8",
        EXTERNAL_NET: "!$HOME_NET,any",
        HTTP_SERVERS: "$HOME_NET",
        SMTP_SERVERS: "$HOME_NET",
        SQL_SERVERS: "$HOME_NET",
        DNS_SERVERS: "$HOME_NET",
        TELNET_SERVERS: "$HOME_NET",
        SNMP_SERVERS: "$HOME_NET",
        FTP_SERVERS: "$HOME_NET",
        SSH_SERVERS: "$HOME_NET",
        SIP_SERVERS: "$HOME_NET",
        HTTP_PORTS: "80,443",
        SHELLCODE_PORTS: "!80",
        ORACLE_PORTS: "1521",
        SSH_PORTS: "22",
        FTP_PORTS: "21,2100,3535",
        SIP_PORTS: "5060,5061",
        FILE_DATA_PORTS: "110,143",
        GTP_PORTS: "2123,2152,3386",
      };
      return examples[name] || "";
    };

    const handleCurrentChange = (page) => {
      currentPage.value = page;
      loadRules();
    };

    const handleSearch = () => {
      currentPage.value = 1; // 搜索时重置到第一页
      loadRules();
    };

    const handleFilter = () => {
      currentPage.value = 1; // 筛选时重置到第一页
      loadRules();
    };

    // 监听页面变化，在全选模式下保持用户的选择状态
    watch(currentPage, () => {
      if (selectAllMode.value) {
        // 延迟执行，确保数据已加载
        nextTick(() => {
          // 在全选模式下，默认所有规则都被选中，除非在排除列表中
          rules.value.forEach((rule) => {
            const shouldSelect = !excludedRules.value.includes(rule.rule_id);
            rulesTableRef.value?.toggleRowSelection(rule, shouldSelect);
          });
          // 更新selectedRules为当前页面被选中的规则
          selectedRules.value = rules.value.filter(
            (rule) => !excludedRules.value.includes(rule.rule_id),
          );
        });
      }
    });

    onMounted(() => {
      loadRules();
    });

    return {
      rules,
      loading,
      submitting,
      importing,
      showCreateDialog,
      showImportDialog,
      isEditing,
      importTab,
      currentPage,
      pageSize,
      totalRules,
      ruleForm,
      ruleFormRef,
      snortUploadRef,
      jsonRulesText,
      snortVariables,
      loadingVariables,
      ruleRules,
      patternRules,
      uploadHeaders,
      getCategoryType,
      getPriorityType,
      getPatternPreview,
      getPatternList,
      formatDate,
      loadRules,
      toggleRule,
      editRule,
      deleteRule,
      submitRule,
      resetForm,
      handleCreateRule,
      handleSnortImportSuccess,
      handleImportError,
      beforeSnortUpload,
      importJsonRules,
      handleImportTabClick,
      loadSnortVariables,
      updateVariable,
      handleCurrentChange,
      addPattern,
      removePattern,
      submitForm,
      cancelEdit,
      // 批量操作
      rulesTableRef,
      selectedRules,
      batchDeleting,
      selectAllMode,
      allSelectedRuleIds,
      excludedRules,
      handleSelectionChange,
      selectAllRules,
      clearSelection,
      batchDeleteRules,
      // 搜索和筛选
      searchText,
      filterCategory,
      filterTags,
      filteredRules,
      handleSearch,
      handleFilter,
      apiBase,
    };
  },
};
</script>

<style scoped>
/* 减小所有输入框和选择框placeholder的字体大小 */
:deep(.el-input__inner::placeholder) {
  font-size: 12px;
}

:deep(.el-select__placeholder) {
  font-size: 12px;
}

.rules-container {
  padding: 20px;
  background-color: #f5f7fa;
  min-height: 100vh;
  width: 100%;
  margin: 0 auto;
  box-sizing: border-box;
}

/* 头部区域样式 */
.rules-header {
  background: white;
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 20px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.1);
}

.header-wrapper {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  max-width: 100%;
}

.header-title {
  display: flex;
  align-items: center;
  font-size: 18px;
  font-weight: 600;
  color: #303133;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 16px;
}

/* 规则计数在头部显示 */
.rules-count-header {
  margin-left: auto;
  margin-right: 20px;
}

/* 移除原来的卡片样式 */
.rules-card {
  border: none;
  border-radius: 12px;
  max-width: 100%;
  width: 100%;
  box-sizing: border-box;
}

/* 超大屏幕限制最大宽度 */
@media (min-width: 1400px) {
  .rules-container {
    max-width: 1400px;
    margin: 0 auto;
  }
}

.header-wrapper {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  max-width: 100%;
}

.header-title {
  display: flex;
  align-items: center;
  font-size: 18px;
  font-weight: 600;
  color: #303133;
  flex-shrink: 1;
  min-width: 0;
}

.title-icon {
  margin-right: 8px;
  color: #409eff;
  flex-shrink: 0;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  max-width: 100%;
}

.search-input {
  width: 250px;
}

.filter-input {
  width: 120px;
}

.action-btn {
  flex-shrink: 0;
}

.rules-table {
  border-radius: 8px;
  overflow: hidden;
  font-size: 12px;
  min-width: 100%;
  width: 100%;
}

.rules-table .el-table__cell {
  padding: 6px 4px;
}

.tags-summary {
  color: #409eff;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  text-decoration: underline;
  text-decoration-color: #409eff;
  text-decoration-style: dotted;
}

.tags-summary:hover {
  color: #337ecc;
}

.no-tags {
  color: #909399;
  font-size: 12px;
}

.pagination-wrapper {
  display: flex;
  justify-content: center;
  margin-top: 20px;
}

.import-section {
  padding: 20px 0;
}

.upload-demo {
  width: 100%;
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

.dialog-footer-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  width: 100%;
}

.rule-format-info {
  margin-bottom: 20px;
}

.format-description {
  line-height: 1.6;
}

.format-description h4 {
  margin: 16px 0 8px 0;
  color: #409eff;
  font-size: 14px;
  font-weight: 600;
}

.format-description ul {
  margin: 8px 0;
  padding-left: 20px;
}

.format-description li {
  margin: 4px 0;
  color: #606266;
}

.format-description strong {
  color: #303133;
}

.syntax-examples {
  margin-top: 12px;
}

.syntax-group {
  margin-bottom: 16px;
  padding: 12px;
  background: #fafafa;
  border-radius: 6px;
  border-left: 3px solid #409eff;
}

.syntax-group h5 {
  margin: 0 0 8px 0;
  color: #409eff;
  font-size: 14px;
  font-weight: 600;
}

.syntax-group ul {
  margin: 8px 0;
  padding-left: 16px;
}

.syntax-group li {
  margin: 6px 0;
  color: #606266;
  line-height: 1.5;
}

.syntax-group code {
  background: #f6f8fa;
  padding: 2px 6px;
  border-radius: 3px;
  font-family: "Monaco", "Menlo", "Ubuntu Mono", monospace;
  font-size: 12px;
  color: #d73a49;
  word-break: break-all;
}

.snort-format-info {
  line-height: 1.6;
}

.snort-format-info ul {
  margin: 8px 0;
  padding-left: 20px;
}

.snort-format-info li {
  margin: 4px 0;
  color: #606266;
  font-size: 13px;
}

.snort-format-info code {
  background: #f6f8fa;
  padding: 2px 6px;
  border-radius: 3px;
  font-family: "Monaco", "Menlo", "Ubuntu Mono", monospace;
  font-size: 12px;
  color: #d73a49;
  display: block;
  margin: 8px 0;
  word-break: break-all;
}

.snort-examples {
  margin-top: 12px;
}

.snort-group {
  margin-bottom: 16px;
  padding: 12px;
  background: #fafafa;
  border-radius: 6px;
  border-left: 3px solid #67c23a;
}

.snort-group h5 {
  margin: 0 0 8px 0;
  color: #67c23a;
  font-size: 14px;
  font-weight: 600;
}

.snort-group p {
  margin: 4px 0;
  color: #909399;
  font-size: 12px;
}

.snort-group ul {
  margin: 8px 0;
  padding-left: 16px;
}

.snort-group li {
  margin: 4px 0;
  color: #606266;
  font-size: 13px;
}

.snort-group code {
  background: #f6f8fa;
  padding: 1px 4px;
  border-radius: 2px;
  font-family: "Monaco", "Menlo", "Ubuntu Mono", monospace;
  font-size: 11px;
  color: #d73a49;
}

.pattern-display {
  display: flex;
  align-items: center;
  gap: 8px;
}

.pattern-text {
  font-family: "Monaco", "Menlo", "Ubuntu Mono", monospace;
  font-size: 12px;
  color: #606266;
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* 高级选项样式 */
.advanced-options {
  margin-top: 16px;
}

.advanced-options :deep(.el-collapse-item__header) {
  background-color: #f8f9fa;
  border-radius: 6px;
  margin-bottom: 8px;
  font-weight: 600;
  color: #409eff;
}

.advanced-options :deep(.el-collapse-item__wrap) {
  border-bottom: 1px solid #ebeef5;
  border-radius: 0 0 6px 6px;
}

.advanced-options-grid {
  padding: 8px 0;
}

.option-description {
  font-size: 12px;
  color: #909399;
  margin-top: 4px;
  line-height: 1.4;
}

.advanced-options .el-form-item {
  margin-bottom: 16px;
}

.advanced-options .el-form-item__label {
  font-weight: 500;
  color: #606266;
}

/* Snort变量配置样式 */
.variables-grid {
  margin-top: 16px;
}

.variables-grid .el-row {
  margin-bottom: 16px;
  padding: 12px;
  background-color: #fafafa;
  border-radius: 6px;
  border: 1px solid #ebeef5;
}

.variable-description {
  font-size: 12px;
  color: #909399;
  margin-bottom: 4px;
}

.variable-description + .el-input {
  margin-top: 0;
}

/* Per-Content 选项样式 */
.per-content-options {
  margin-top: 20px;
}

.content-item-config {
  margin-bottom: 16px;
}

.content-card {
  border: 1px solid #ebeef5;
}

.content-header {
  display: flex;
  align-items: center;
  gap: 12px;
}

.content-index {
  font-weight: 600;
  color: #409eff;
  font-size: 14px;
}

.option-description {
  font-size: 12px;
  color: #909399;
  margin-top: 4px;
  line-height: 1.4;
}

/* 表单样式 */
.form-section {
  margin-bottom: 24px;
  border-radius: 8px;
}

.section-header {
  display: flex;
  align-items: center;
  font-size: 16px;
  font-weight: 600;
  color: #303133;
}

.section-header .el-icon {
  margin-right: 8px;
  color: #409eff;
}

.switch-hint {
  margin-left: 12px;
  font-size: 14px;
  color: #909399;
}

.content-match-alert {
  margin-bottom: 20px;
}

.content-match-alert .el-alert__description {
  font-size: 14px;
  line-height: 1.5;
  color: #606266;
}

.pattern-card {
  margin-bottom: 16px;
  border-radius: 8px;
}

.pattern-card:hover {
  border-color: #c8e1ff;
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
}

.pattern-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid #e1e4e8;
}

.pattern-title {
  font-weight: 600;
  color: #24292f;
  font-size: 14px;
}

/* 表单项样式优化 */
.pattern-form-item .el-form-item__label {
  font-weight: 500;
  color: #606266;
  margin-bottom: 6px;
}

.pattern-form-item .el-input__inner,
.pattern-form-item .el-select .el-input__inner {
  border-radius: 4px;
}

.pattern-form-item .el-checkbox__label {
  font-size: 13px;
  color: #606266;
}

.pattern-item {
  margin-bottom: 16px;
}

.pattern-card {
  border: 1px solid #ebeef5;
  border-radius: 6px;
}

.pattern-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
}

.add-pattern-btn {
  width: 100%;
  margin-top: 16px;
}

/* 响应式设计 */
@media (max-width: 1200px) {
  .header-wrapper {
    flex-direction: column;
    align-items: flex-start;
    gap: 16px;
  }

  .header-actions {
    width: 100%;
    justify-content: flex-start;
    flex-wrap: wrap;
    gap: 8px;
    max-width: 100%;
  }

  .search-input {
    flex: 1;
    min-width: 200px;
    max-width: 300px;
  }

  .filter-input {
    flex: 1;
    min-width: 120px;
    max-width: 150px;
  }

  .action-btn {
    min-width: 100px;
    flex-shrink: 0;
  }
}

@media (max-width: 768px) {
  .rules-container {
    padding: 10px;
  }

  .header-wrapper {
    gap: 12px;
  }

  .header-title {
    font-size: 16px;
  }

  .header-actions {
    flex-direction: row;
    flex-wrap: wrap;
    justify-content: flex-start;
    gap: 8px;
    width: 100%;
  }

  .search-input,
  .filter-input {
    width: 100% !important;
    max-width: none !important;
  }

  .action-btn {
    width: 100%;
    min-width: auto;
  }

  .rules-table {
    font-size: 11px;
  }

  .rules-table .el-table__cell {
    padding: 4px 3px;
  }
}

@media (max-width: 480px) {
  .rules-container {
    padding: 5px;
  }

  .header-title {
    font-size: 14px;
  }

  .title-icon {
    margin-right: 4px;
  }

  .rules-card {
    margin: 0;
  }

  .rules-table {
    font-size: 10px;
  }

  .pattern-text {
    max-width: 120px;
  }

  .batch-actions {
    margin-bottom: 16px;
    padding: 12px;
    background: #f8f9fa;
    border-radius: 4px;
    border: 1px solid #e9ecef;
  }

  .select-all-hint {
    margin-left: 16px;
    color: #409eff;
    font-weight: 500;
  }
}

.info-icon {
  color: #909399;
  cursor: help;
  font-size: 14px;
}

/* 操作按钮样式 */
.action-buttons {
  display: flex;
  gap: 4px;
  justify-content: center;
  align-items: center;
}

.action-buttons .el-button {
  padding: 4px 8px;
  font-size: 12px;
  min-width: 40px;
}
</style>
