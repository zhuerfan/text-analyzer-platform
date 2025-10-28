// ===========================
// 前端 script.js（加密文件本地解密版）
// 说明：从 ./data_encrypted/*.enc 拉取 base64 内容，使用用户输入密码通过 PBKDF2 -> AES-GCM 解密
// 与本地 encrypt_data.py 保持参数一致：SALT_LEN=16, IV_LEN=12, ITERATIONS=200000, AES-256-GCM
// ===========================

// ---------- 配置 ----------
const ENC_BASE = "./data_encrypted"; // 存放 .enc 文件的相对路径（调整为你 GitHub Pages 的路径）
const SALT_LEN = 16;
const IV_LEN = 12;
const PBKDF2_ITER = 200000;
const KEY_LEN = 256; // bits

// ---------- 全局数据（原来在 loadData 内的变量已提升为全局） ----------
let charFreqData = [], charCohesionData = [], charSummaryData = [], charNetworkData = null;
let rawTextData = []; // 存储原始文本数据 (array of lines objects)
let currentHighlightIndex = -1, currentSelectedIndex = -1;
let charts = {};
let currentHighlightedChar = null;
let highlightedSpans = [];
const chinaColors = ["#c23531","#2f4554","#61a0a8","#d48265","#91c7ae","#749f83","#ca8622","#bda29a","#6e7074","#546570"];
let currentHighlightedNode = null; // 当前高亮的节点
let isFullscreen = false; // 是否全屏模式
let lastCheckedIndex = -1; // 用于Shift连续选择
let isShiftPressed = false; // 是否按下了Shift键
let originalNodeSizes = {}; // 存储原始节点大小
let originalNodeColors = {}; // 存储原始节点颜色
let labelsVisible = true; // 控制标签显示状态
let currentSortColumn = ''; // 当前排序列
let sortDirection = 'desc'; // 排序方向
let nodeSizeScale = 1.0; // 节点尺寸比例
let edgeWidthScale = 1.0; // 边宽比例

// ===========================
// Web Crypto 解密工具
// ===========================
function base64ToArrayBuffer(b64) {
  const binary_string = atob(b64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary_string.charCodeAt(i);
  return bytes.buffer;
}

async function deriveKey(password, salt) {
  const pwUtf8 = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey(
    "raw",
    pwUtf8,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITER,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: KEY_LEN },
    false,
    ["decrypt"]
  );
  return key;
}

async function decryptPayloadBase64(b64payload, password) {
  // payload = salt(16) || iv(12) || ciphertext
  const buffer = base64ToArrayBuffer(b64payload.trim());
  const bytes = new Uint8Array(buffer);
  if (bytes.length < SALT_LEN + IV_LEN + 16) {
    throw new Error("加密文件长度异常");
  }
  const salt = bytes.slice(0, SALT_LEN);
  const iv = bytes.slice(SALT_LEN, SALT_LEN + IV_LEN);
  const ct = bytes.slice(SALT_LEN + IV_LEN);

  const key = await deriveKey(password, salt);
  try {
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      ct
    );
    return new Uint8Array(plainBuf);
  } catch (e) {
    throw new Error("解密失败：可能密码错误或文件已损坏");
  }
}

function uint8ToString(u8) {
  return new TextDecoder().decode(u8);
}

// ===========================
// fetch + 解密的高阶函数
// ===========================
async function fetchEncAsText(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`无法获取加密文件: ${url} (status ${r.status})`);
  return (await r.text()).trim();
}

async function fetchAndDecryptJson(urlEnc, password) {
  const b64 = await fetchEncAsText(urlEnc);
  const plainBytes = await decryptPayloadBase64(b64, password);
  const text = uint8ToString(plainBytes);
  return JSON.parse(text);
}

async function fetchAndDecryptText(urlEnc, password) {
  const b64 = await fetchEncAsText(urlEnc);
  const plainBytes = await decryptPayloadBase64(b64, password);
  return uint8ToString(plainBytes);
}

// ===========================
// 登录（本地密码解密）逻辑：用户输入密码 -> 解密所有 .enc 文件 -> 初始化页面
// ===========================
document.getElementById("loginBtn").addEventListener("click", async () => {
  const pwd = document.getElementById("passwordInput").value;
  const errorDiv = document.getElementById("loginError");
  const loading = document.getElementById("loading");
  errorDiv.style.display = "none";
  loading.style.display = "block";

  try {
    // 依次拉取并解密（按需可并行）
    const base = ENC_BASE.replace(/\/$/, "");
    const p = pwd;

    // 使用 Promise.all 并行加速
    const [
      charFreq,
      charCohesion,
      charSummary,
      charNetwork,
      rawText
    ] = await Promise.all([
      fetchAndDecryptJson(`${base}/char_freq.json.enc`, p),
      fetchAndDecryptJson(`${base}/char_cohesion.json.enc`, p),
      fetchAndDecryptJson(`${base}/char_summary.json.enc`, p),
      fetchAndDecryptJson(`${base}/char_network.json.enc`, p),
      fetchAndDecryptText(`${base}/raw_text.txt.enc`, p)
    ]);

    // 解密成功，赋值全局变量
    charFreqData = Array.isArray(charFreq) ? charFreq : (charFreq.records || []);
    charCohesionData = Array.isArray(charCohesion) ? charCohesion : (charCohesion.records || []);
    charSummaryData = Array.isArray(charSummary) ? charSummary : (charSummary.records || []);
    charNetworkData = charNetwork || { nodes: [], links: [] };

    // rawText 变成字符串 -> 处理成 rawTextData 结构
    processRawText(rawText);

    // 隐藏登录，显示主界面
    document.getElementById("loginModal").style.display = "none";
    document.getElementById("app").style.display = "flex";

    // 初始化界面（渲染表格、图表等）
    renderCharFreqTable(charFreqData);
    renderDetailedContent();
    renderSummaryStats();
    updateCharts();
    loadCheckedState();
    positionDownloadButtons();

  } catch (err) {
    console.error("解密或加载失败：", err);
    errorDiv.textContent = "密码错误或数据加载失败，请重试。";
    errorDiv.style.display = "block";
  } finally {
    loading.style.display = "none";
  }
});

// ===========================
// 以下为你原始脚本中的所有逻辑（我保留并改为使用上面全局变量）
// 你原来写在 loadData() 内的大部分函数已被提取到全局作用域并使用全局数据
// 下面直接复制并略微调整：
// ===========================

// ====== 本地存储勾选状态 ======
function saveCheckedState() {
    const checkedChars = Array.from(document.querySelectorAll('.charCheck')).map(cb => ({
        char: charFreqData[cb.dataset.idx].char,
        checked: cb.checked
    }));
    localStorage.setItem('checkedChars', JSON.stringify(checkedChars));
}

function loadCheckedState() {
    const stored = JSON.parse(localStorage.getItem('checkedChars') || '[]');
    document.querySelectorAll('.charCheck').forEach(cb => {
        const found = stored.find(s => s.char === charFreqData[cb.dataset.idx].char);
        if (found) cb.checked = found.checked;
    });
}

// ====== 处理原始文本 ======
function processRawText(text) {
    rawTextData = [];
    const lines = text.split('\n');

    lines.forEach((line, lineIndex) => {
        if (line.trim() === '') return;

        // 清理文本：保留中文字符和常见标点
        const cleanedLine = line.replace(/[^\u4e00-\u9fa5，。！？；："「」『』《》【】、]/g, '');
        const chars = cleanedLine.split('');

        rawTextData.push({
            lineNumber: lineIndex + 1,
            chars: chars,
            text: cleanedLine
        });
    });

    console.log('处理后的文本数据:', rawTextData);
}

// ====== 渲染字频表 ======
function renderCharFreqTable(data) {
    const tbody = document.querySelector('#charFreqTable tbody');
    tbody.innerHTML = '';
    data.forEach((item, idx) => {
        const tr = document.createElement('tr');
        tr.dataset.char = item.char;
        tr.dataset.idx = idx;
        tr.innerHTML = `<td><input type="checkbox" class="charCheck" data-idx="${idx}"></td>
                        <td>${item.char}</td><td>${item.freq}</td>`;
        const cb = tr.querySelector('input');
        cb.addEventListener('change', (e) => {
            handleCheckboxChange(e, idx);
            updateCharts();
            saveCheckedState();
        });
        tr.addEventListener('click', (e) => {
            if (e.target.tagName !== 'INPUT') {
                highlightCharFromLeft(item.char);
                if (charts.cohesionChart) {
                    highlightNodeAndRelated(item.char);
                    showCohesionStats(item.char);
                }
            }
        });
        tbody.appendChild(tr);
    });
}

// ====== 处理复选框变化（支持Shift连续选择） ======
function handleCheckboxChange(e, currentIndex) {
    if (isShiftPressed && lastCheckedIndex !== -1 && lastCheckedIndex !== currentIndex) {
        const start = Math.min(lastCheckedIndex, currentIndex);
        const end = Math.max(lastCheckedIndex, currentIndex);
        const checkboxes = document.querySelectorAll('.charCheck');
        for (let i = start; i <= end; i++) {
            checkboxes[i].checked = e.target.checked;
        }
    }
    lastCheckedIndex = currentIndex;
}

// ====== 全选 ======
document.getElementById('selectAll').addEventListener('change', function () {
    const checked = this.checked;
    document.querySelectorAll('.charCheck').forEach(cb => cb.checked = checked);
    updateCharts();
    saveCheckedState();
});

// ====== 获取勾选的字 ======
function getCheckedChars() {
    const checked = Array.from(document.querySelectorAll('.charCheck:checked')).map(cb => {
        const idx = parseInt(cb.dataset.idx, 10);
        return charFreqData[idx];
    }).filter(Boolean);

    // 如果没有选中任何字符，默认显示前50个高频字符
    if (checked.length === 0 && charFreqData.length > 0) {
        return charFreqData.slice(0, Math.min(50, charFreqData.length));
    }

    return checked;
}

// ====== 更新图表 ======
function updateCharts() {
    renderCharts(getCheckedChars());
}

// ====== 渲染单字序列 ======
function renderDetailedContent() {
    const container = document.getElementById('detailedContent');
    container.innerHTML = '';

    if (rawTextData.length === 0) {
        container.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">暂无文本数据</div>';
        return;
    }

    rawTextData.forEach(lineData => {
        const lineDiv = document.createElement('div');
        lineDiv.className = 'text-line';

        const lineNumberSpan = document.createElement('span');
        lineNumberSpan.className = 'line-number';
        lineNumberSpan.textContent = lineData.lineNumber;
        lineDiv.appendChild(lineNumberSpan);

        lineData.chars.forEach((char, charIndex) => {
            const charSpan = document.createElement('span');
            charSpan.className = 'single-char normalWord';
            charSpan.textContent = char;
            charSpan.dataset.char = char;
            charSpan.dataset.line = lineData.lineNumber;
            charSpan.dataset.idx = charIndex;

            charSpan.addEventListener('click', () => {
                highlightCharFromRight(char, {
                    line: lineData.lineNumber,
                    idx: charIndex,
                    text: lineData.text
                });
                if (charts.cohesionChart) {
                    highlightNodeAndRelated(char);
                    showCohesionStats(char);
                }
            });

            lineDiv.appendChild(charSpan);
        });

        container.appendChild(lineDiv);
    });
}

// ====== 高亮（左/右） ======
function highlightCharFromLeft(keyword) {
    clearHighlights();
    currentHighlightedChar = keyword;

    // 高亮左侧字频表
    document.querySelectorAll('#charFreqTable tbody tr').forEach(tr => {
        tr.classList.toggle('highlightRow', tr.dataset.char === keyword);
    });

    // 高亮右侧单字序列
    highlightedSpans = [];
    document.querySelectorAll('#detailedContent .single-char').forEach(span => {
        if (span.dataset.char === keyword) {
            span.classList.add('highlightRight');
            highlightedSpans.push(span);
        }
    });

    if (highlightedSpans.length > 0) {
        currentHighlightIndex = 0;
        highlightedSpans[0].classList.add('highlightSelected');
        highlightedSpans[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    const charData = charFreqData.find(item => item.char === keyword);
    if (charData) {
        document.getElementById('info').textContent = `字: ${keyword}, 频率: ${charData.freq}, 出现次数: ${highlightedSpans.length}`;
    }
}

function highlightCharFromRight(char, item) {
    clearHighlights();
    currentHighlightedChar = char;

    // 高亮左侧字频表
    document.querySelectorAll('#charFreqTable tbody tr').forEach(tr => {
        if (tr.dataset.char === char) {
            tr.classList.add('highlightRow');
            tr.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    });

    // 高亮右侧单字序列
    highlightedSpans = [];
    document.querySelectorAll('#detailedContent .single-char').forEach(span => {
        if (span.dataset.char === char) {
            span.classList.add('highlightRight');
            highlightedSpans.push(span);
            if (span.dataset.line === item.line.toString() && span.dataset.idx === item.idx.toString()) {
                span.classList.add('highlightSelected');
                currentHighlightIndex = highlightedSpans.length - 1;
            }
        }
    });

    document.getElementById('info').textContent = `行: ${item.line}, 位置: ${item.idx}, 文本: ${item.text}`;
}

function clearHighlights() {
    document.querySelectorAll('#charFreqTable tbody tr').forEach(tr => tr.classList.remove('highlightRow'));
    document.querySelectorAll('#detailedContent .single-char').forEach(span => {
        span.classList.remove('highlightRight');
        span.classList.remove('highlightSelected');
    });
    currentHighlightedChar = null;
    highlightedSpans = [];
    currentHighlightIndex = -1;
    document.getElementById('info').textContent = '';
    if (charts.cohesionChart) {
        resetNetworkChart();
        hideCohesionStats();
    }
}

function navigateToNextHighlight() {
    if (highlightedSpans.length === 0) return;
    highlightedSpans[currentHighlightIndex].classList.remove('highlightSelected');
    currentHighlightIndex = (currentHighlightIndex + 1) % highlightedSpans.length;
    highlightedSpans[currentHighlightIndex].classList.add('highlightSelected');
    highlightedSpans[currentHighlightIndex].scrollIntoView({ behavior: 'smooth', block: 'center' });

    const span = highlightedSpans[currentHighlightIndex];
    const lineData = rawTextData.find(line => line.lineNumber === parseInt(span.dataset.line));
    if (lineData) {
        document.getElementById('info').textContent = `行: ${span.dataset.line}, 位置: ${span.dataset.idx}, 文本: ${lineData.text}`;
    }
}

// ====== 左右搜索（模糊匹配） ======
const searchLeft = () => {
    const k = document.getElementById('searchInput').value.trim();
    if (!k) return;
    document.querySelectorAll('#charFreqTable tbody tr').forEach(tr => {
        tr.classList.toggle('highlightRow', tr.dataset.char.includes(k));
    });
}

const searchRight = () => {
    const k = document.getElementById('detailedSearchInput').value.trim();
    if (!k) return;

    clearHighlights();
    currentHighlightedChar = k;

    // 高亮右侧单字序列
    highlightedSpans = [];
    document.querySelectorAll('#detailedContent .single-char').forEach(span => {
        if (span.dataset.char === k) {
            span.classList.add('highlightRight');
            highlightedSpans.push(span);
        }
    });

    if (highlightedSpans.length > 0) {
        currentHighlightIndex = 0;
        highlightedSpans[0].classList.add('highlightSelected');
        highlightedSpans[0].scrollIntoView({ behavior: 'smooth', block: 'center' });

        // 高亮左侧字频表
        document.querySelectorAll('#charFreqTable tbody tr').forEach(tr => {
            tr.classList.toggle('highlightRow', tr.dataset.char === k);
        });

        const charData = charFreqData.find(item => item.char === k);
        if (charData) {
            document.getElementById('info').textContent = `字: ${k}, 频率: ${charData.freq}, 出现次数: ${highlightedSpans.length}`;
        }
    }
}

// ====== 全屏切换 ======
function toggleFullscreen() {
    isFullscreen = !isFullscreen;
    const chartsElement = document.getElementById('charts');
    const detailedElement = document.getElementById('detailed');
    const fullscreenBtn = document.getElementById('fullscreenBtn');
    if (isFullscreen) {
        document.body.classList.add('fullscreen');
        fullscreenBtn.textContent = '取消全屏';
        detailedElement.style.display = 'none';
        chartsElement.style.height = '100%';
        setTimeout(() => Object.values(charts).forEach(chart => chart?.resize?.()), 100);
    } else {
        document.body.classList.remove('fullscreen');
        fullscreenBtn.textContent = '全屏';
        detailedElement.style.display = 'block';
        chartsElement.style.height = '';
        setTimeout(() => Object.values(charts).forEach(chart => chart?.resize?.()), 100);
    }
}

// ====== 搜索 & 键盘 ======
document.getElementById('searchBtn').addEventListener('click', searchLeft);
document.getElementById('searchInput').addEventListener('keydown', e => { if (e.key === 'Enter') searchLeft(); });
document.getElementById('detailedSearchBtn').addEventListener('click', searchRight);
document.getElementById('detailedSearchInput').addEventListener('keydown', e => { if (e.key === 'Enter') searchRight(); });
document.getElementById('fullscreenBtn').addEventListener('click', toggleFullscreen);
document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && currentHighlightedChar) navigateToNextHighlight();
    if (e.key === 'Shift') { isShiftPressed = true; document.body.classList.add('shift-selecting'); }
});
document.addEventListener('keyup', (e) => { if (e.key === 'Shift') { isShiftPressed = false; document.body.classList.remove('shift-selecting'); } });
document.addEventListener('DOMContentLoaded', function() {
    // 节点尺寸滑块
    const nodeSizeSlider = document.getElementById('nodeSizeSlider');
    const nodeSizeValue = document.getElementById('nodeSizeValue');

    if (nodeSizeSlider) {
        nodeSizeSlider.addEventListener('input', function() {
            nodeSizeScale = parseFloat(this.value);
            nodeSizeValue.textContent = nodeSizeScale.toFixed(1);
            updateNetworkScales();
        });
    }

    // 边宽滑块
    const edgeWidthSlider = document.getElementById('edgeWidthSlider');
    const edgeWidthValue = document.getElementById('edgeWidthValue');

    if (edgeWidthSlider) {
        edgeWidthSlider.addEventListener('input', function() {
            edgeWidthScale = parseFloat(this.value);
            edgeWidthValue.textContent = edgeWidthScale.toFixed(1);
            updateNetworkScales();
        });
    }
});

// ====== ECharts 图表渲染 ======
function renderCharts(data) {
    console.log('开始渲染图表，数据量:', data.length);
    console.log('当前激活的标签页:', document.querySelector('#chartTabs button.active').dataset.target);

    if (data.length === 0) {
        console.warn('没有选中的字符数据，图表将为空');
    }
    // 单字云图
    if (document.getElementById('charCloud').classList.contains('active')) {
        charts.charCloud = echarts.init(document.getElementById('charCloud'));

        // 全局最大字频（防 0）
        const globalMaxFreq = Math.max(...charFreqData.map(d => d.freq), 1);

        // 选中字 + 两个不可见锚点（把缩放固定到 [0, globalMaxFreq]）
        const wcData = [
            ...data.map(d => ({ name: d.char, value: d.freq })),
            { name: '\u200B', value: 0, textStyle: { color: 'rgba(0,0,0,0)' }, tooltip: { show: false } },
            { name: '\u200B\u200B', value: globalMaxFreq, textStyle: { color: 'rgba(0,0,0,0)' }, tooltip: { show: false } }
        ];

        charts.charCloud.setOption({
            series: [{
                type: 'wordCloud',
                gridSize: 8,
                sizeRange: [12, 100],
                rotationRange: [0, 0],
                shape: 'circle',
                textStyle: { color: () => chinaColors[Math.floor(Math.random() * chinaColors.length)] },
                data: wcData
            }]
        });

        charts.charCloud.off('click');
        charts.charCloud.on('click', p => {
            // 忽略不可见锚点
            if (p.name && p.name.trim() !== '') {
                highlightCharFromLeft(p.name);
                if (charts.cohesionChart) {
                    highlightNodeAndRelated(p.name);
                    showCohesionStats(p.name);
                }
            }
        });
    }

    // 柱状图
    if (document.getElementById('barChart').classList.contains('active')) {
        charts.barChart = echarts.init(document.getElementById('barChart'));
        const topData = data.slice().sort((a, b) => b.freq - a.freq).slice(0, 100);
        charts.barChart.setOption({
            grid: { left: 50, right: 50, top: 20, bottom: 80 },
            xAxis: { type: 'category', data: topData.map(d => d.char), axisLabel: { interval: 0, rotate: 45, fontSize: 12 } },
            yAxis: { type: 'value' },
            series: [{ type: 'bar', data: topData.map(d => d.freq) }],
            dataZoom: [{ type: 'slider', show: true, xAxisIndex: 0, start: 0, end: 20 }]
        });
        charts.barChart.on('click', p => {
            highlightCharFromLeft(p.name);
            if (charts.cohesionChart) {
                highlightNodeAndRelated(p.name);
                showCohesionStats(p.name);
            }
        });
    }

    // 黏着度网络图
    if (document.getElementById('cohesionChart').classList.contains('active')) {
        renderCohesionChart();
    }

    // 汇总统计图
    if (document.getElementById('summaryChart').classList.contains('active')) {
        renderSummaryChart();
    }
    // 在所有图表渲染完成后，确保它们正确调整大小
    setTimeout(() => {
        Object.values(charts).forEach(chart => {
            if (chart && typeof chart.resize === 'function') {
                chart.resize();
            }
        });
    }, 100);
}

// ====== 渲染黏着度网络图 ======
function renderCohesionChart() {
    if (!charNetworkData || !charNetworkData.nodes || !charNetworkData.links) {
        console.error('网络数据无效');
        return;
    }

    const checkedChars = getCheckedChars().map(item => item.char);
    const filteredNodes = charNetworkData.nodes.filter(node => checkedChars.includes(node.id));
    const filteredLinks = charNetworkData.links.filter(link =>
        checkedChars.includes(link.source) && checkedChars.includes(link.target));

    if (charts.cohesionChart) charts.cohesionChart.dispose();
    charts.cohesionChart = echarts.init(document.getElementById('networkChartContainer'));

    const nodeCount = filteredNodes.length;
    const repulsion = Math.max(200, nodeCount * 10);
    const baseEdgeLen = Math.max(100, nodeCount * 5);

    const nodeValues = filteredNodes.map(n => n.value);
    const maxNodeValue = Math.max(...nodeValues, 1);
    const minNodeValue = Math.min(...nodeValues, 0);

    // 记录原始样式
    originalNodeSizes = {};
    originalNodeColors = {};
    filteredNodes.forEach((node, i) => {
        // 确保节点大小在合理范围内
        let size = 10 + (node.value - minNodeValue) / ((maxNodeValue - minNodeValue) || 1) * 30;
        size = Math.max(8, Math.min(size, 40)); // 限制节点大小在8-40之间
        originalNodeSizes[node.id] = size;
        originalNodeColors[node.id] = chinaColors[i % chinaColors.length];
    });

    const option = {
        title: { text: '单字黏着度网络（显示已勾选的字）', top: 'top', left: 'center' },
        tooltip: {
            confine: true,
            formatter: function(params) {
                if (params.dataType === 'node') {
                    const name = params.data.name;
                    const freq = charFreqData.find(d => d.char === name)?.freq || 0;

                    // 获取该字的黏着度信息
                    const cohesionInfo = charCohesionData.filter(item => item.center_char === name);
                    const leftCohesion = cohesionInfo.filter(item => item.direction === 'left');
                    const rightCohesion = cohesionInfo.filter(item => item.direction === 'right');

                    let tooltipContent = `<b>${name}</b><br/>字频: ${freq}<br/>`;

                    if (leftCohesion.length > 0) {
                        tooltipContent += `<b>左邻字:</b><br/>`;
                        leftCohesion.slice(0, 5).forEach(item => {
                            tooltipContent += `${item.neighbor_char}: ${item.cohesion_count}<br/>`;
                        });
                    }

                    if (rightCohesion.length > 0) {
                        tooltipContent += `<b>右邻字:</b><br/>`;
                        rightCohesion.slice(0, 5).forEach(item => {
                            tooltipContent += `${item.neighbor_char}: ${item.cohesion_count}<br/>`;
                        });
                    }

                    return tooltipContent;
                } else if (params.dataType === 'edge') {
                    const s = params.data.source, t = params.data.target;
                    // 查找黏着度信息
                    const cohesion = charCohesionData.find(item =>
                        (item.center_char === s && item.neighbor_char === t) ||
                        (item.center_char === t && item.neighbor_char === s)
                    );

                    return `<b>${s}</b> ↔ <b>${t}</b><br/>黏着次数: ${cohesion ? cohesion.cohesion_count : '未知'}`;
                }
                return '';
            }
        },
        animation: true,
        animationDuration: 1500,
        animationEasingUpdate: 'quinticInOut',
        series: [{
            type: 'graph',
            layout: 'force',
            force: {
                repulsion,
                edgeLength: baseEdgeLen,
                gravity: 0.1,
                friction: 0.6,
                layoutAnimation: true
            },
            data: filteredNodes.map((node, index) => ({
                id: node.id,
                name: node.name,
                value: node.value,
                symbolSize: originalNodeSizes[node.id] * nodeSizeScale, // 应用节点尺寸比例
                itemStyle: { color: originalNodeColors[node.id], opacity: 1 },
                label: {
                    show: labelsVisible,
                    position: 'right',
                    formatter: '{b}',
                    fontSize: 8 + (node.value - minNodeValue) / ((maxNodeValue - minNodeValue)||1) * 8
                },
                emphasis: { label: { show: true } }
            })),
            links: filteredLinks.map(link => ({
                source: link.source,
                target: link.target,
                value: link.value,
                edgeLength: baseEdgeLen,
                lineStyle: {
                    width: 2 * edgeWidthScale, // 应用边宽比例
                    opacity: 0.8,
                    curveness: 0.2,
                    color: '#ccc'
                }
            })),
            roam: true,
            focusNodeAdjacency: true,
            lineStyle: { opacity: 0.9, width: 2 * edgeWidthScale, curveness: 0.2 }, // 应用边宽比例
            emphasis: { focus: 'adjacency', lineStyle: { width: 5 * edgeWidthScale } } // 应用边宽比例
        }]
    };

    charts.cohesionChart.setOption(option);

    charts.cohesionChart.off('click');
    charts.cohesionChart.on('click', params => {
        if (params.dataType === 'node') {
            highlightNodeAndRelated(params.data.name);
            showCohesionStats(params.data.name);
        } else if (!params.dataType) {
            resetNetworkChart();
            hideCohesionStats();
        }
    });

    window.addEventListener('resize', () => {
        if (charts.cohesionChart) {
            charts.cohesionChart.resize();
            positionDownloadButtons();
        }
    });
}

// ====== 渲染汇总统计图 ======
function renderSummaryChart() {
    if (!charSummaryData || charSummaryData.length === 0) return;

    charts.summaryChart = echarts.init(document.getElementById('summaryChart'));

    // 按总黏着度排序
    const sortedData = charSummaryData.slice().sort((a, b) => b.total_cohesion - a.total_cohesion).slice(0, 20);

    const option = {
        title: { text: '单字黏着度汇总统计（前20）', left: 'center' },
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow' }
        },
        legend: {
            data: ['左邻黏着度', '右邻黏着度', '总黏着度']
        },
        grid: {
            left: '3%',
            right: '4%',
            bottom: '3%',
            containLabel: true
        },
        xAxis: {
            type: 'value'
        },
        yAxis: {
            type: 'category',
            data: sortedData.map(d => d.char)
        },
        series: [
            {
                name: '左邻黏着度',
                type: 'bar',
                stack: 'total',
                emphasis: { focus: 'series' },
                data: sortedData.map(d => d.left_cohesion_count)
            },
            {
                name: '右邻黏着度',
                type: 'bar',
                stack: 'total',
                emphasis: { focus: 'series' },
                data: sortedData.map(d => d.right_cohesion_count)
            },
            {
                name: '总黏着度',
                type: 'bar',
                label: {
                    show: true,
                    position: 'right'
                },
                data: sortedData.map(d => d.total_cohesion)
            }
        ]
    };

    charts.summaryChart.setOption(option);

    charts.summaryChart.off('click');
    charts.summaryChart.on('click', params => {
        if (params.componentType === 'series' && params.seriesType === 'bar') {
            const char = sortedData[params.dataIndex].char;
            highlightCharFromLeft(char);
            showCohesionStats(char);
        }
    });
}

// ====== 黏着度统计悬浮窗 ======
function showCohesionStats(centerChar) {
    const statsTable = document.querySelector('#cohesionStatsTable tbody');
    statsTable.innerHTML = '';
    document.getElementById('currentCenterChar').textContent = centerChar;

    // 获取该字的黏着度信息
    const cohesionInfo = charCohesionData.filter(item => item.center_char === centerChar);

    if (cohesionInfo.length > 0) {
        // 按黏着次数排序
        cohesionInfo.sort((a, b) => b.cohesion_count - a.cohesion_count);

        cohesionInfo.forEach(item => {
            const row = document.createElement('tr');
            row.innerHTML = `<td>${item.neighbor_char}</td><td>${item.direction === 'left' ? '左邻' : '右邻'}</td><td>${item.cohesion_count}</td>`;
            statsTable.appendChild(row);
        });

        document.getElementById('cohesionStats').style.display = 'block';
    } else {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="3">暂无黏着度数据</td>';
        statsTable.appendChild(row);
        document.getElementById('cohesionStats').style.display = 'block';
    }
}

function hideCohesionStats() {
    document.getElementById('cohesionStats').style.display = 'none';
}

// ====== 网络图高亮功能 ======
function highlightNodeAndRelated(nodeName) {
    // 点击同一个节点再次点按则重置
    if (currentHighlightedNode === nodeName) {
        resetNetworkChart();
        hideCohesionStats();
        return;
    }
    currentHighlightedNode = nodeName;

    const option = charts.cohesionChart.getOption();
    const series = option.series[0];

    // 获取与该字有黏着关系的字
    const relatedChars = charCohesionData
        .filter(item => item.center_char === nodeName)
        .map(item => item.neighbor_char);

    // 更新节点显示：中心节点与其邻居突出显示，其他节点变淡
    series.data.forEach(node => {
        if (node.id === nodeName) {
            // 中心节点：稍微放大并添加边框
            const baseSize = originalNodeSizes[node.id] || 20;
            node.symbolSize = Math.min(baseSize * 1.5, 50) * nodeSizeScale; // 应用节点尺寸比例
            node.itemStyle = { ...node.itemStyle, opacity: 1, borderWidth: 3, borderColor: '#ff0000' };
            node.label = { ...node.label, show: true, fontWeight: 'bold' };
        } else if (relatedChars.includes(node.id)) {
            // 关联节点：适度放大，基于黏着度但限制范围
            const cohesion = charCohesionData.find(item =>
                item.center_char === nodeName && item.neighbor_char === node.id
            );
            const cohesionCount = cohesion ? cohesion.cohesion_count : 1;
            const baseSize = originalNodeSizes[node.id] || 20;

            // 限制放大倍数和最大尺寸
            const sizeMultiplier = Math.min(1 + (cohesionCount * 0.1), 1.8); // 最大放大1.8倍
            node.symbolSize = Math.min(baseSize * sizeMultiplier, 40) * nodeSizeScale; // 应用节点尺寸比例

            node.itemStyle = { ...node.itemStyle, opacity: 1, borderWidth: 0 };
            node.label = {
                ...node.label,
                show: true,
                fontSize: Math.min(12 + cohesionCount * 0.3, 16) // 限制字体最大为16
            };
        } else {
            node.itemStyle = { ...node.itemStyle, opacity: 0.08 };
            node.label = { ...node.label, show: false };
        }
    });

    // 更新边：对与中心节点直接相连的边，按黏着度决定粗细和颜色
    series.links.forEach(link => {
        const s = link.source, t = link.target;
        // 检查是否与中心词相连
        if (s === nodeName || t === nodeName) {
            const other = (s === nodeName) ? t : s;
            const cohesion = charCohesionData.find(item =>
                (item.center_char === nodeName && item.neighbor_char === other) ||
                (item.center_char === other && item.neighbor_char === nodeName)
            );

            const cohesionCount = cohesion ? cohesion.cohesion_count : 1;
            const width = Math.min(10, 2 + cohesionCount * 0.5) * edgeWidthScale; // 应用边宽比例

            // 颜色由黏着度决定
            const color = getCohesionColor(cohesionCount);

            link.lineStyle = { ...link.lineStyle, width: width, opacity: 1, color: color };
        } else {
            // 非关联边降淡
            link.lineStyle = { ...link.lineStyle, opacity: 0.08, color: '#DDDDDD', width: 1 * edgeWidthScale }; // 应用边宽比例
        }
    });

    charts.cohesionChart.setOption(option);
}

// 根据黏着度获取颜色
function getCohesionColor(count) {
    if (count >= 10) return '#c23531'; // 红色，高黏着
    if (count >= 5) return '#d48265';  // 橙色，中高黏着
    if (count >= 3) return '#91c7ae';  // 绿色，中黏着
    if (count >= 1) return '#61a0a8';  // 蓝色，低黏着
    return '#ccc'; // 灰色，无黏着
}

// 重置网络图样式
function resetNetworkChart() {
    currentHighlightedNode = null;
    const option = charts.cohesionChart.getOption();
    const series = option.series[0];

    series.data.forEach(node => {
        node.symbolSize = (originalNodeSizes[node.id] || 20) * nodeSizeScale; // 应用节点尺寸比例
        node.itemStyle = { ...node.itemStyle, opacity: 1, borderWidth: 0, color: originalNodeColors[node.id] || '#c23531' };
        node.label = { ...node.label, show: labelsVisible, fontWeight: 'normal', fontSize: 12 };
    });
    series.links.forEach(link => {
        link.lineStyle = { ...link.lineStyle, opacity: 0.8, width: 2 * edgeWidthScale, color: '#ccc' }; // 应用边宽比例
        link.edgeLength = (series.force && series.force.edgeLength) ? series.force.edgeLength : 150;
    });
    charts.cohesionChart.setOption(option);
}

// ====== 更新网络图比例 ======
function updateNetworkScales() {
    if (charts.cohesionChart) {
        // 如果是高亮状态，重新应用高亮
        if (currentHighlightedNode) {
            highlightNodeAndRelated(currentHighlightedNode);
        } else {
            // 否则重置到普通状态
            resetNetworkChart();
        }
    }
}

// ====== 汇总统计 ======
function renderSummaryStats() {
    if (!charSummaryData || charSummaryData.length === 0) return;

    const tbody = document.querySelector('#summaryTable tbody');
    tbody.innerHTML = '';

    // 计算总体统计
    const totalChars = charSummaryData.length;
    const totalCohesion = charSummaryData.reduce((sum, item) => sum + item.total_cohesion, 0);
    const avgCohesion = totalCohesion / totalChars;

    const stats = [
        { name: '总字数', value: totalChars },
        { name: '总黏着次数', value: totalCohesion },
        { name: '平均黏着度', value: avgCohesion.toFixed(2) },
        { name: '最高频率字', value: `${charFreqData[0]?.char || ''} (${charFreqData[0]?.freq || 0})` },
        { name: '最高黏着字', value: `${charSummaryData[0]?.char || ''} (${charSummaryData[0]?.total_cohesion || 0})` }
    ];

    stats.forEach(stat => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${stat.name}</td><td>${stat.value}</td>`;
        tbody.appendChild(tr);
    });
}

// ====== Tab 切换 ======
document.querySelectorAll('#chartTabs button').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('#chartTabs button').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.chartBox').forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        const target = document.getElementById(btn.dataset.target);
        target.classList.add('active');

        if (btn.dataset.target === 'cohesionChart') {
            document.getElementById('networkChartContainer').style.height = '400px';
            renderCohesionChart();
        }
        if (charts[btn.dataset.target]) {
            charts[btn.dataset.target].resize();
        } else {
            updateCharts();
        }
    });
});

// ====== 黏着度悬浮窗拖动 ======
const cohesionStats = document.getElementById('cohesionStats');
const cohesionHeader = document.getElementById('cohesionStatsHeader');
let isDraggingCohesion = false, offsetXCohesion = 0, offsetYCohesion = 0;
cohesionHeader.addEventListener('mousedown', e => {
    isDraggingCohesion = true;
    offsetXCohesion = e.clientX - cohesionStats.offsetLeft;
    offsetYCohesion = e.clientY - cohesionStats.offsetTop;
});
document.addEventListener('mousemove', e => {
    if (isDraggingCohesion) {
        cohesionStats.style.left = (e.clientX - offsetXCohesion) + 'px';
        cohesionStats.style.top = (e.clientY - offsetYCohesion) + 'px';
    }
});
document.addEventListener('mouseup', () => isDraggingCohesion = false);

// ====== 汇总统计悬浮窗拖动 ======
const summaryStats = document.getElementById('summaryStats');
const summaryHeader = document.getElementById('summaryStatsHeader');
let isDraggingSummary = false, offsetXSummary = 0, offsetYSummary = 0;
summaryHeader.addEventListener('mousedown', e => {
    isDraggingSummary = true;
    offsetXSummary = e.clientX - summaryStats.offsetLeft;
    offsetYSummary = e.clientY - summaryStats.offsetTop;
});
document.addEventListener('mousemove', e => {
    if (isDraggingSummary) {
        summaryStats.style.left = (e.clientX - offsetXSummary) + 'px';
        summaryStats.style.top = (e.clientY - offsetYSummary) + 'px';
    }
});
document.addEventListener('mouseup', () => isDraggingSummary = false);

// ====== 表格排序功能 ======
document.querySelectorAll('#cohesionStatsTable th').forEach(header => {
    header.addEventListener('click', () => {
        const column = header.dataset.sort;
        const tbody = document.querySelector('#cohesionStatsTable tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));

        if (rows.length === 0) return;

        const data = rows.map(row => {
            const cells = row.querySelectorAll('td');
            return {
                char: cells[0].textContent,
                direction: cells[1].textContent,
                count: parseInt(cells[2].textContent) || 0,
                element: row
            };
        });

        // 切换排序方向
        if (currentSortColumn === column) {
            sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            currentSortColumn = column;
            sortDirection = 'desc';
        }

        // 排序数据
        data.sort((a, b) => {
            let valA = a[column];
            let valB = b[column];

            if (sortDirection === 'asc') {
                return valA > valB ? 1 : -1;
            } else {
                return valA < valB ? 1 : -1;
            }
        });

        // 重新渲染表格
        tbody.innerHTML = '';
        data.forEach(item => {
            tbody.appendChild(item.element);
        });

        // 更新排序指示器
        updateSortIndicators();
    });
});

// 更新排序指示器
function updateSortIndicators() {
    const headers = document.querySelectorAll('#cohesionStatsTable th');
    headers.forEach(header => {
        const indicator = header.querySelector('.sort-indicator');
        if (header.dataset.sort === currentSortColumn) {
            indicator.textContent = sortDirection === 'asc' ? '↑' : '↓';
        } else {
            indicator.textContent = '↕';
        }
    });
}

// ====== 取消高亮按钮 ======
document.getElementById('clearHighlights').addEventListener('click', clearHighlights);

// ====== 更新网络按钮 ======
document.getElementById('updateNetwork').addEventListener('click', () => {
    renderCohesionChart();
});

// ====== 下载图表图片功能 ======
function positionDownloadButtons() {
    document.querySelectorAll('.chartBox').forEach(box => {
        if (box.classList.contains('active')) {
            const downloadBtn = box.querySelector('.download-btn');
            if (downloadBtn) {
                // 确保按钮始终可见
                downloadBtn.style.display = 'block';
            }
        }
    });
}

document.querySelectorAll('.download-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const chartType = btn.getAttribute('data-chart');
        if (charts[chartType]) {
            const url = charts[chartType].getDataURL({
                type: 'png',
                pixelRatio: 2,
                backgroundColor: '#fff'
            });
            const a = document.createElement('a');
            a.href = url;
            a.download = `${chartType}_${new Date().getTime()}.png`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }
    });
});

// ====== 随机配色功能 ======
function generateRandomColors(count) {
    const colors = [];
    // 使用chinaColors中的颜色，随机排序
    const shuffledColors = [...chinaColors].sort(() => Math.random() - 0.5);

    for (let i = 0; i < count; i++) {
        // 循环使用随机排序后的chinaColors
        colors.push(shuffledColors[i % shuffledColors.length]);
    }
    return colors;
}

document.getElementById('randomColorsBtn').addEventListener('click', () => {
    // 生成新的随机颜色（基于chinaColors的随机排序）
    const newColors = generateRandomColors(chinaColors.length);

    // 更新全局颜色数组
    chinaColors.splice(0, chinaColors.length, ...newColors);

    // 重新渲染所有图表
    updateCharts();

    // 重新渲染网络图
    if (charNetworkData) {
        renderCohesionChart();
    }
});

// ====== 切换标签显示功能 ======
document.getElementById('toggleLabelsBtn').addEventListener('click', () => {
    labelsVisible = !labelsVisible;

    // 更新网络图
    if (charts.cohesionChart && charNetworkData) {
        const option = charts.cohesionChart.getOption();
        if (option.series && option.series[0] && option.series[0].data) {
            option.series[0].data.forEach(node => {
                if (node.label) {
                    node.label.show = labelsVisible;
                }
            });
            charts.cohesionChart.setOption(option);
        }
    }

    // 更新按钮文本
    document.getElementById('toggleLabelsBtn').textContent =
        labelsVisible ? '隐藏标签' : '显示标签';
});

// ====== 汇总统计悬浮窗展开/收起 ======
document.getElementById('toggleSummary').addEventListener('click', () => {
    const table = document.querySelector('#summaryTable');
    if (table.style.display === 'none') {
        table.style.display = 'table';
        document.getElementById('toggleSummary').textContent = '➖';
    } else {
        table.style.display = 'none';
        document.getElementById('toggleSummary').textContent = '➕';
    }
});

// ====== 黏着度悬浮窗展开/收起 ======
document.getElementById('toggleCohesion').addEventListener('click', () => {
    const table = document.querySelector('#cohesionStatsTable');
    if (table.style.display === 'none') {
        table.style.display = 'table';
        document.getElementById('toggleCohesion').textContent = '➖';
    } else {
        table.style.display = 'none';
        document.getElementById('toggleCohesion').textContent = '➕';
    }
});

// ====== 初始化相关（页面加载时的一些绑定） ======
window.addEventListener('resize', function() {
    Object.values(charts).forEach(chart => chart?.resize?.());
    positionDownloadButtons();
});

// 初始定位下载按钮（当用户已经登录并解密成功会再次调用）
setTimeout(positionDownloadButtons, 100);
