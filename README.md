# SafeVibe

Explainable multi-signal risk assessment for phishing, scams and malicious content.
(ITE 3965 Final Year Project, K.S.S. Perera, E2529010)

## Run the backend
```bash
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
# API docs: http://localhost:8000/docs
pytest
```

## Layout
- `backend/app/input_manager` validation + URL canonicalisation
- `backend/app/analyzers` message, URL (more to come)
- `backend/app/risk` weighted scoring (weights_v1.yaml)
- `backend/rules` versioned rule files
- `docs/traceability.md` SRS -> code -> test
