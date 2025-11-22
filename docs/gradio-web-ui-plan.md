# Purviewer Gradio Web UI Plan

**Created**: November 21, 2025
**Status**: Planning
**Target Version**: v0.6.0
**Priority**: High - Enables staff adoption

---

## Executive Summary

Add a lightweight Gradio web interface to Purviewer that allows non-technical staff to analyze Entra ID sign-in logs through a browser. The UI provides file upload, parameter configuration, and report download functionality without requiring CLI knowledge.

---

## Why Gradio?

| Feature | Gradio | Streamlit | Plotly Dash |
|---------|--------|-----------|-------------|
| Setup Complexity | Minimal | Low | Medium |
| Resource Usage | ~50MB RAM | ~100MB RAM | ~150MB RAM |
| File Handling | Built-in | Built-in | Manual |
| Learning Curve | Hours | Days | Days |
| Docker Image | Small | Medium | Large |
| No JavaScript | Yes | Yes | No |

**Decision**: Gradio is ideal for the "upload → process → download" workflow with minimal overhead.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              Gradio Web Interface           │
│  ┌─────────────┐  ┌─────────────────────┐   │
│  │ File Upload │  │ Parameter Controls  │   │
│  └──────┬──────┘  └──────────┬──────────┘   │
│         │                    │              │
│         ▼                    ▼              │
│  ┌─────────────────────────────────────┐    │
│  │        Analysis Orchestrator        │    │
│  └──────────────────┬──────────────────┘    │
│                     │                       │
│         ┌───────────┼───────────┐           │
│         ▼           ▼           ▼           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐     │
│  │ Markdown │ │   JSON   │ │   CSV    │     │
│  │  Report  │ │  Report  │ │ Anomalies│     │
│  └──────────┘ └──────────┘ └──────────┘     │
└─────────────────────────────────────────────┘
```

---

## File Structure

```
src/purviewer/
├── web/
│   ├── __init__.py           # Module exports
│   ├── app.py                # Gradio app definition
│   ├── handlers.py           # Analysis handler functions
│   └── components.py         # Reusable UI components
└── main.py                   # Add --web flag

docs/
└── gradio-web-ui-plan.md     # This plan
```

---

## UI Components

### 1. File Upload Section

```python
with gr.Row():
    file_input = gr.File(
        label="Upload Sign-In Logs",
        file_types=[".json", ".csv"],
        type="filepath"
    )
```

**Features**:
- Accept JSON and CSV files
- Show file name and size after upload
- Validate file format before processing

### 2. Analysis Options

```python
with gr.Accordion("Analysis Options", open=True):
    with gr.Row():
        enable_anomalies = gr.Checkbox(
            label="Enable Anomaly Detection",
            value=True
        )
        enable_ml = gr.Checkbox(
            label="Enable ML Detection",
            value=False
        )

    user_filter = gr.Textbox(
        label="Filter by User (optional)",
        placeholder="john.doe@contoso.com"
    )
```

**Options mapped from CLI**:
- `--entra-anomalies` → Enable Anomaly Detection checkbox
- `--entra-ml-detect` → Enable ML Detection checkbox
- `--entra-user` → User filter textbox

### 3. Advanced Settings (Collapsible)

```python
with gr.Accordion("Advanced Settings", open=False):
    max_speed = gr.Slider(
        label="Max Travel Speed (km/h)",
        minimum=500,
        maximum=2000,
        value=900,
        step=50
    )

    z_score_threshold = gr.Slider(
        label="Failure Spike Threshold (σ)",
        minimum=2.0,
        maximum=5.0,
        value=3.0,
        step=0.5
    )

    geoip_db = gr.File(
        label="MaxMind GeoLite2 Database (optional)",
        file_types=[".mmdb"]
    )
```

### 4. Action Button

```python
analyze_btn = gr.Button(
    "Analyze Sign-In Logs",
    variant="primary",
    size="lg"
)
```

### 5. Output Section

```python
with gr.Tabs():
    with gr.Tab("Summary"):
        summary_output = gr.Markdown()

    with gr.Tab("Full Report"):
        report_output = gr.Markdown()

    with gr.Tab("Raw Data"):
        json_output = gr.JSON()
```

### 6. Download Section

```python
with gr.Row():
    md_download = gr.File(label="Download Markdown Report")
    json_download = gr.File(label="Download JSON Report")
    csv_download = gr.File(label="Download Anomalies CSV")
```

---

## Implementation Plan

### Phase 1: Core UI (2-3 hours)

**1.1 Create Web Module**
- File: `src/purviewer/web/__init__.py`
- Export main app and launch function

**1.2 Build Main App**
- File: `src/purviewer/web/app.py`
- Define Gradio interface with all components
- Set up event handlers

**1.3 Implement Handlers**
- File: `src/purviewer/web/handlers.py`
- `analyze_logs()` - Main analysis function
- `generate_reports()` - Create downloadable files
- `validate_input()` - Pre-processing validation

### Phase 2: Integration (1-2 hours)

**2.1 Connect to Existing Analyzers**
- Import `EntraAnomalyAnalyzer`
- Import `EntraDataLoader`
- Import `EntraReportGenerator`

**2.2 File Handling**
- Process uploaded files
- Generate temporary output files
- Clean up after download

**2.3 Error Handling**
- Display user-friendly error messages
- Log detailed errors for debugging
- Handle malformed input gracefully

### Phase 3: CLI Integration (30 min)

**3.1 Add Web Flag**
- File: `src/purviewer/main.py`
- Add `--web` argument to launch Gradio
- Add `--web-port` for custom port

```python
web_group = parser.add_argument_group("Web Interface")
web_group.add_argument(
    "--web",
    action="store_true",
    help="launch Gradio web interface"
)
web_group.add_argument(
    "--web-port",
    type=int,
    default=7860,
    help="port for web interface (default: 7860)"
)
```

### Phase 4: Polish (1 hour)

**4.1 Styling**
- Custom CSS for branding
- Responsive layout
- Dark/light theme support

**4.2 Documentation**
- Update README with web UI instructions
- Add example screenshots
- Document deployment options

---

## Dependencies

### New Dependencies

```toml
[tool.poetry.dependencies]
gradio = "^4.0"
```

**Why Gradio 4.x**:
- Better file handling
- Improved performance
- Smaller bundle size
- Active maintenance

### Estimated Impact
- Additional ~30MB disk space
- ~50MB runtime memory
- No additional system dependencies

---

## Usage Examples

### Launch Web UI

```bash
# Default port (7860)
purviewer --web

# Custom port
purviewer --web --web-port 8080
```

### Docker Deployment

```dockerfile
FROM python:3.13-slim

WORKDIR /app
COPY . .

RUN pip install poetry && \
    poetry install --no-dev

EXPOSE 7860

CMD ["poetry", "run", "purviewer", "--web"]
```

### Behind Caddy (user's environment)

```caddyfile
purviewer.internal.domain {
    reverse_proxy localhost:7860
}
```

---

## UI Mockup

```
┌─────────────────────────────────────────────────────────┐
│  🔍 Purviewer - Entra Sign-In Analysis                  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  📁 Upload Sign-In Logs                                 │
│  ┌─────────────────────────────────────────────┐        │
│  │  Drag and drop file here                    │        │
│  │  - or -                                     │        │
│  │  Click to upload (.json, .csv)              │        │
│  └─────────────────────────────────────────────┘        │
│                                                         │
│  ⚙️ Analysis Options                                    │
│  ┌─────────────────────────────────────────────┐        │
│  │ ☑ Enable Anomaly Detection                  │        │
│  │ ☐ Enable ML Detection (Isolation Forest)    │        │
│  │                                             │        │
│  │ Filter by User: [_______________________]   │        │
│  └─────────────────────────────────────────────┘        │
│                                                         │
│  ▶ Advanced Settings                                    │
│                                                         │
│  ┌─────────────────────────────────────────────┐        │
│  │         🔍 Analyze Sign-In Logs             │        │
│  └─────────────────────────────────────────────┘        │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  📊 Results                                             │
│  ┌─────────────────────────────────────────────┐        │
│  │ [Summary] [Full Report] [Raw Data]          │        │
│  ├─────────────────────────────────────────────┤        │
│  │                                             │        │
│  │  ## Executive Summary                       │        │
│  │                                             │        │
│  │  **CRITICAL**: 2 high-confidence            │        │
│  │  compromise(s) detected.                    │        │
│  │                                             │        │
│  │  ### Anomaly Summary                        │        │
│  │  - Impossible Travel: 27                    │        │
│  │  - New Locations: 20                        │        │
│  │  - New Devices: 5                           │        │
│  │  - Failure Spikes: 0                        │        │
│  │                                             │        │
│  └─────────────────────────────────────────────┘        │
│                                                         │
│  📥 Download Reports                                    │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐                  │
│  │   MD    │  │  JSON   │  │   CSV   │                  │
│  └─────────┘  └─────────┘  └─────────┘                  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Success Criteria

### Functional
- [ ] Upload JSON/CSV sign-in logs
- [ ] Configure all analysis options via UI
- [ ] Display analysis results in browser
- [ ] Download Markdown, JSON, and CSV reports
- [ ] Handle errors gracefully with user feedback

### Non-Functional
- [ ] Launch in < 3 seconds
- [ ] Process 1000 records in < 10 seconds
- [ ] Memory usage < 100MB idle
- [ ] Works in Chrome, Firefox, Edge

### User Experience
- [ ] Non-technical staff can use without training
- [ ] Clear feedback during processing
- [ ] Intuitive layout and controls

---

## Testing Strategy

### Manual Testing
1. Upload various file sizes (10, 100, 1000+ records)
2. Test all parameter combinations
3. Verify report downloads work
4. Test error scenarios (malformed files, empty files)

### Browser Testing
- Chrome (primary)
- Firefox
- Edge
- Safari (if accessible)

---

## Git Workflow

```bash
# Create feature branch
git checkout -b feature/gradio-web-ui

# Implement in commits:
# 1. feat(web): add gradio web interface skeleton
# 2. feat(web): implement analysis handlers
# 3. feat(web): add file download functionality
# 4. feat(web): integrate with CLI --web flag
# 5. docs: add web UI documentation

# Create PR to main
```

---

## Timeline

| Phase | Estimated Time |
|-------|----------------|
| Phase 1: Core UI | 2-3 hours |
| Phase 2: Integration | 1-2 hours |
| Phase 3: CLI Integration | 30 min |
| Phase 4: Polish | 1 hour |
| **Total** | **4-6 hours** |

---

## Future Enhancements (Post v0.6.0)

- **Batch Processing**: Upload multiple files
- **Scheduled Analysis**: Cron-based automatic analysis
- **User Authentication**: Restrict access to authorized users
- **API Endpoint**: REST API alongside web UI
- **Dashboard**: Real-time monitoring visualization

---

## Notes

- Docker setup will be handled in user's separate environment
- Caddy reverse proxy configuration provided by user
- Focus on simplicity and low resource usage
- No database required - stateless processing only

---

**Next Action**: Create feature branch and implement Phase 1.
