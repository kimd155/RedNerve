import socketio
import traceback


def register_events(sio: socketio.AsyncServer):
    @sio.event
    async def connect(sid, environ):
        print(f"[WS] Client connected: {sid}")

        # Reuse latest session with messages, or create a fresh one
        try:
            from services.session_service import session_service
            session = await session_service.get_latest_active_session()
            if not session:
                session = await session_service.get_or_create_session()
            await sio.emit("session_info", session, to=sid)
            print(f"[WS] Session for {sid}: {session['id']}")
        except Exception as e:
            print(f"[WS] Session creation error: {e}")
            traceback.print_exc()

    @sio.event
    async def disconnect(sid):
        print(f"[WS] Client disconnected: {sid}")

    @sio.on("cancel_operation")
    async def handle_cancel_operation(sid, data):
        """Operator cancels the current operation."""
        print(f"[WS] cancel_operation from {sid}")
        try:
            from orchestrator.orchestrator import orchestrator
            session_id = data.get("session_id") if data else None
            if session_id:
                orchestrator.cancel(session_id)
        except Exception as e:
            print(f"[WS] Cancel error: {e}")

    @sio.on("send_message")
    async def handle_send_message(sid, data):
        """Operator sends a command — route through orchestrator."""
        print(f"[WS] send_message from {sid}: {str(data)[:100]}")
        from orchestrator.orchestrator import orchestrator

        session_id = data.get("session_id")
        content = data.get("content", "").strip()

        if not content:
            return

        await sio.emit("typing_start", {"session_id": session_id, "status": "Processing..."})

        try:
            response = await orchestrator.handle_message(session_id, content, sio=sio)
            await sio.emit("typing_end", {"session_id": session_id})
            await sio.emit("new_message", response)
        except Exception as e:
            print(f"[WS] Orchestrator error: {e}")
            traceback.print_exc()
            await sio.emit("typing_end", {"session_id": session_id})
            import time
            await sio.emit("new_message", {
                "id": f"error-{int(time.time() * 1000)}",
                "sequence": -1,
                "role": "system",
                "content": f"Error: {str(e)}",
                "metadata": {"error": True},
            })

    @sio.on("request_history")
    async def handle_request_history(sid, data):
        try:
            from services.chat_service import chat_service
            session_id = data.get("session_id")
            since = data.get("since_sequence", 0)
            messages = await chat_service.get_messages(session_id, since_sequence=since)
            await sio.emit("chat_history", {"messages": messages}, to=sid)
        except Exception as e:
            print(f"[WS] History error: {e}")
            traceback.print_exc()
            await sio.emit("chat_history", {"messages": []}, to=sid)

    @sio.on("request_session")
    async def handle_request_session(sid, data=None):
        try:
            from services.session_service import session_service
            session = await session_service.get_or_create_session()
            await sio.emit("session_info", session, to=sid)
            print(f"[WS] Session sent to {sid}: {session['id']}")
        except Exception as e:
            print(f"[WS] Session error: {e}")
            traceback.print_exc()

    @sio.on("request_beacon_session")
    async def handle_request_beacon_session(sid, data):
        """Open or create a session scoped to a specific beacon."""
        try:
            from services.session_service import session_service
            from server.beacon_handler import beacon_handler
            beacon_id = data.get("beacon_id") if data else None
            if not beacon_id:
                return
            session = await session_service.get_or_create_session(beacon_id=beacon_id)
            # Enrich with beacon info
            beacon = await beacon_handler.get_beacon(beacon_id)
            if beacon:
                session["beacon_hostname"] = beacon.get("hostname", "")
                session["beacon_ip"] = beacon.get("ip_address", "")
            await sio.emit("session_info", session, to=sid)
            print(f"[WS] Beacon session for {sid}: {session['id']} (beacon={beacon_id})")
        except Exception as e:
            print(f"[WS] Beacon session error: {e}")
            traceback.print_exc()

    @sio.on("request_sessions")
    async def handle_request_sessions(sid, data=None):
        """Return list of all chat sessions for the sidebar."""
        try:
            from services.session_service import session_service
            from server.beacon_handler import beacon_handler
            sessions = await session_service.list_sessions()
            # Enrich beacon sessions with hostname
            beacons_cache = {}
            for s in sessions:
                bid = s.get("beacon_id")
                if bid:
                    if bid not in beacons_cache:
                        beacons_cache[bid] = await beacon_handler.get_beacon(bid)
                    b = beacons_cache[bid]
                    if b:
                        s["beacon_hostname"] = b.get("hostname", "")
                        s["beacon_ip"] = b.get("ip_address", "")
            await sio.emit("sessions_list", {"sessions": sessions}, to=sid)
        except Exception as e:
            print(f"[WS] Sessions list error: {e}")
            traceback.print_exc()
            await sio.emit("sessions_list", {"sessions": []}, to=sid)

    @sio.on("switch_session")
    async def handle_switch_session(sid, data):
        """Switch to an existing session or create a new one."""
        try:
            from services.session_service import session_service
            session_id = data.get("session_id") if data else None

            if session_id == "new":
                session = await session_service.get_or_create_session()
            else:
                session = await session_service.get_or_create_session(session_id)

            await sio.emit("session_info", session, to=sid)
            print(f"[WS] Switched session for {sid}: {session['id']}")
        except Exception as e:
            print(f"[WS] Switch session error: {e}")
            traceback.print_exc()

    @sio.on("delete_session")
    async def handle_delete_session(sid, data):
        """Delete a session and its messages."""
        try:
            from services.session_service import session_service
            session_id = data.get("session_id") if data else None
            if session_id:
                result = await session_service.delete_session(session_id)
                await sio.emit("session_deleted", {"session_id": session_id, **result}, to=sid)
        except Exception as e:
            print(f"[WS] Delete session error: {e}")
            traceback.print_exc()

    @sio.on("delete_beacon")
    async def handle_delete_beacon(sid, data):
        """Delete a beacon from the targets list."""
        try:
            from server.beacon_handler import beacon_handler
            beacon_id = data.get("beacon_id") if data else None
            if beacon_id:
                result = await beacon_handler.delete_beacon(beacon_id)
                if result.get("deleted"):
                    await sio.emit("beacon_deleted", {"beacon_id": beacon_id})
        except Exception as e:
            print(f"[WS] Delete beacon error: {e}")

    @sio.on("request_targets")
    async def handle_request_targets(sid, data=None):
        try:
            from server.beacon_handler import beacon_handler
            beacons = await beacon_handler.list_beacons()
            await sio.emit("targets_list", {"targets": beacons}, to=sid)
        except Exception as e:
            print(f"[WS] Targets error: {e}")
            await sio.emit("targets_list", {"targets": []}, to=sid)

    @sio.on("generate_report")
    async def handle_generate_report(sid, data=None):
        """Start background report generation."""
        try:
            from services.report_service import report_service
            agent_filter = data.get("agent_filter", "all") if data else "all"
            result = await report_service.start_generation(sio=sio, agent_filter=agent_filter)
            await sio.emit("report_started", result, to=sid)
        except Exception as e:
            print(f"[WS] Report generation error: {e}")
            traceback.print_exc()

    @sio.on("request_reports")
    async def handle_request_reports(sid, data=None):
        """Return list of all reports."""
        try:
            from services.report_service import report_service
            reports = await report_service.list_reports()
            await sio.emit("reports_list", {"reports": reports}, to=sid)
        except Exception as e:
            print(f"[WS] Reports list error: {e}")
            await sio.emit("reports_list", {"reports": []}, to=sid)

    @sio.on("request_findings_summary")
    async def handle_request_findings_summary(sid, data=None):
        """Return findings grouped by beacon for the dashboard."""
        try:
            from services.findings_service import findings_service
            summary = await findings_service.get_findings_summary_by_beacon()
            await sio.emit("findings_summary", {"beacons": summary}, to=sid)
        except Exception as e:
            print(f"[WS] Findings summary error: {e}")
            traceback.print_exc()
            await sio.emit("findings_summary", {"beacons": []}, to=sid)

    @sio.on("request_recent_logs")
    async def handle_request_recent_logs(sid, data=None):
        """Return recent log entries for the dashboard activity feed."""
        try:
            from services.log_service import log_service
            logs = await log_service.get_logs(limit=50)
            await sio.emit("recent_logs", {"logs": logs}, to=sid)
        except Exception as e:
            print(f"[WS] Recent logs error: {e}")
            await sio.emit("recent_logs", {"logs": []}, to=sid)

    @sio.on("request_agent_status")
    async def handle_request_agent_status(sid, data=None):
        try:
            from agents.registry import registry
            statuses = {}
            for name, agent in registry.all().items():
                statuses[name] = {
                    "name": name,
                    "description": agent.description,
                    "capabilities": agent.capabilities,
                    "status": "ready",
                }
            await sio.emit("agent_status_update", {"agents": statuses}, to=sid)
        except Exception as e:
            print(f"[WS] Agent status error: {e}")
