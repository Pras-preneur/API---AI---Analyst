import pytest
import uuid
from app.models import (
    session_store,
    SessionStore,
    TestStatus,
    FindingStatus,
    ProposedTest,
    Finding,
    Evidence,
    EndpointModel,
)

# Helper to create a minimal EndpointModel instance (structure based on parser)
def dummy_endpoint():
    """Create a minimal valid ``EndpointModel`` instance.

    The ``EndpointModel`` requires a ``responses`` mapping. We provide a simple
    ``200`` response with a description, which satisfies the Pydantic schema.
    """
    # ``responses`` can be a dict of raw data; Pydantic will coerce to ``ResponseModel``.
    return EndpointModel(
        path="/test",
        method="GET",
        responses={"200": {"description": "OK"}},
    )

def test_session_creation_and_unique_ids():
    sid1 = session_store.create_session()
    sid2 = session_store.create_session()
    assert isinstance(sid1, str)
    assert isinstance(sid2, str)
    assert sid1 != sid2
    # Verify session can be retrieved and has correct ID
    sess1 = session_store.get_session(sid1)
    assert sess1.session_id == sid1

def test_add_and_retrieve_proposal():
    sid = session_store.create_session()
    proposal = ProposedTest(
        endpoint=dummy_endpoint(),
        test_type="BOLA",
        description="Check IDOR",
        severity="High",
    )
    pid = session_store.add_proposal(sid, proposal)
    assert pid == proposal.test_id
    fetched = session_store.get_proposal(sid, pid)
    assert fetched.test_id == proposal.test_id
    assert fetched.status == TestStatus.PROPOSED

def test_proposal_status_transitions():
    sid = session_store.create_session()
    proposal = ProposedTest(
        endpoint=dummy_endpoint(),
        test_type="BFLA",
        description="Check function auth",
        severity="Medium",
    )
    pid = session_store.add_proposal(sid, proposal)
    # Approve
    session_store.set_proposal_status(sid, pid, TestStatus.APPROVED)
    assert session_store.get_proposal(sid, pid).status == TestStatus.APPROVED
    # Reject
    session_store.set_proposal_status(sid, pid, TestStatus.REJECTED)
    assert session_store.get_proposal(sid, pid).status == TestStatus.REJECTED
    # Ensure rejected cannot be set to EXECUTED without explicit transition
    session_store.set_proposal_status(sid, pid, TestStatus.EXECUTED)
    assert session_store.get_proposal(sid, pid).status == TestStatus.EXECUTED

def test_add_and_retrieve_finding():
    sid = session_store.create_session()
    proposal = ProposedTest(
        endpoint=dummy_endpoint(),
        test_type="ExcessiveData",
        description="Check data exposure",
        severity="Low",
    )
    pid = session_store.add_proposal(sid, proposal)
    evidence = Evidence(request={"path": "/test"}, response={"status": 200})
    finding = Finding(
        test_id=pid,
        endpoint=dummy_endpoint(),
        evidence=evidence,
        severity="Low",
    )
    fid = session_store.add_finding(sid, finding)
    assert fid == finding.finding_id
    fetched = session_store.get_finding(sid, fid)
    assert fetched.finding_id == finding.finding_id
    assert fetched.status == FindingStatus.SUSPECTED

def test_session_isolation():
    sid1 = session_store.create_session()
    sid2 = session_store.create_session()
    proposal1 = ProposedTest(
        endpoint=dummy_endpoint(),
        test_type="BOLA",
        description="Session1 test",
        severity="High",
    )
    pid1 = session_store.add_proposal(sid1, proposal1)
    # Ensure sid2 cannot see sid1's proposal
    with pytest.raises(KeyError):
        session_store.get_proposal(sid2, pid1)
    # Ensure unknown session raises
    with pytest.raises(KeyError):
        session_store.get_session(str(uuid.uuid4()))

def test_unknown_proposal_handling():
    sid = session_store.create_session()
    # Access a non‑existent proposal ID
    fake_id = str(uuid.uuid4())
    with pytest.raises(KeyError):
        session_store.get_proposal(sid, fake_id)
    # Attempt to set status on non‑existent proposal
    with pytest.raises(KeyError):
        session_store.set_proposal_status(sid, fake_id, TestStatus.APPROVED)

def test_prevent_implicit_execution_of_rejected():
    sid = session_store.create_session()
    proposal = ProposedTest(
        endpoint=dummy_endpoint(),
        test_type="BFLA",
        description="Reject then exec",
        severity="Medium",
    )
    pid = session_store.add_proposal(sid, proposal)
    session_store.set_proposal_status(sid, pid, TestStatus.REJECTED)
    # Directly trying to set to EXECUTED should be allowed only if explicitly called –
    # this test ensures that the model does not auto‑transition.
    assert session_store.get_proposal(sid, pid).status == TestStatus.REJECTED
    # Explicit transition
    session_store.set_proposal_status(sid, pid, TestStatus.EXECUTED)
    assert session_store.get_proposal(sid, pid).status == TestStatus.EXECUTED
