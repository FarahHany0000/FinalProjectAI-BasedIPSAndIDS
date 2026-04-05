"""API layer - HTTP Controllers and routes"""

from flask import Blueprint, jsonify, request
from extensions import db, socketio
from models.alert import Alert
from ..application import NetworkDetectionService, AlertService
from ..infra import ModelLoader
from datetime import datetime

api_bp = Blueprint('api', __name__, url_prefix='/api')

# Initialize services
model_loader = ModelLoader()
alert_service = AlertService(db)


@api_bp.route('/agent/network-alert', methods=['POST'])
def receive_network_alert():
    """Receive network detection from network sensor"""
    try:
        data = request.get_json()

        # Validate agent key
        agent_key = request.headers.get('X-Agent-Key')
        if not agent_key:
            return jsonify({'error': 'Missing agent key'}), 401

        # Process detection
        detection_service = NetworkDetectionService(None, db)
        alert_domain = detection_service.process_detection(data)

        if not alert_domain:
            return jsonify({'error': 'Invalid detection data'}), 400

        # Convert to ORM model and save
        alert_model = Alert(
            source_type=alert_domain.source_type,
            host_name=alert_domain.host_name,
            ip=alert_domain.ip,
            threat_type=alert_domain.threat_type,
            severity=alert_domain.severity,
            action=alert_domain.action,
            confidence=alert_domain.confidence,
            details=alert_domain.details,
            time=alert_domain.time,
        )

        db.session.add(alert_model)
        db.session.commit()

        # Broadcast to frontend via Socket.IO
        socketio.emit('new_alert', {
            'id': alert_model.id,
            'source_type': alert_model.source_type,
            'threat': alert_model.threat_type,
            'severity': alert_model.severity,
            'action': alert_model.action,
            'confidence': alert_model.confidence,
            'time': alert_model.time.isoformat(),
            'message': f"{alert_model.threat_type} detected",
        }, broadcast=True)

        return jsonify({
            'status': 'success',
            'alert_id': alert_model.id,
            'message': f"{alert_domain.threat_type} recorded"
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@api_bp.route('/alerts', methods=['GET'])
def get_alerts():
    """Get alerts with optional filtering"""
    try:
        limit = request.args.get('limit', 50, type=int)
        source = request.args.get('source', None)
        page = request.args.get('page', 1, type=int)

        query = Alert.query.order_by(Alert.time.desc())

        if source:
            query = query.filter_by(source_type=source)

        total = query.count()
        alerts = query.limit(limit).offset((page - 1) * limit).all()

        return jsonify({
            'items': [a.to_dict() for a in alerts],
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'pages': (total + limit - 1) // limit
            }
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/alerts/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Get single alert by ID"""
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404

        return jsonify(alert.to_dict()), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        total_alerts = Alert.query.count()
        critical_alerts = Alert.query.filter_by(severity='Critical').count()
        network_alerts = Alert.query.filter_by(source_type='network').count()
        blocked_attacks = Alert.query.filter_by(is_blocked=True).count()

        return jsonify({
            'total_alerts': total_alerts,
            'critical_alerts': critical_alerts,
            'network_detections': network_alerts,
            'blocked_attacks': blocked_attacks,
            'system_status': {
                'is_running': True,
                'is_healthy': True,
                'network_sensor_enabled': True,
                'models_loaded': True,
            }
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'components': {
                'database': 'connected',
                'api': 'operational'
            }
        }), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500
