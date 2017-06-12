import result_view_service
from src.app import apks, app, make_celery
from celery import states
from flask import jsonify, url_for
from src.dict_object import DictObject
from src.services import scenario_service
from src.models.smart_input_assignments import SmartInputAssignment


celery = make_celery(app)


class AnalysisState:
    def __init__(self,
                 static_analysis_ids,
                 dynamic_analysis_ids_w_state,
                 html,
                 apk_filename_to_static_analysis_ids,
                 static_analysis_ids_w_activities=None):
        self.poll_url = url_for('get_analysis_status')
        self.static_analysis_ids = static_analysis_ids
        self.dynamic_analysis_ids_w_state = dynamic_analysis_ids_w_state
        self.html = html
        self.apk_filename_to_static_analysis_ids = apk_filename_to_static_analysis_ids
        self.static_analysis_ids_w_activities = static_analysis_ids_w_activities

    def __json__(self):
        return {'poll_url': self.poll_url,
                'static_analysis_ids': self.static_analysis_ids,
                'dynamic_analysis_ids_w_state': self.dynamic_analysis_ids_w_state,
                'html': self.html,
                'apk_filename_to_static_analysis_ids': self.apk_filename_to_static_analysis_ids,
                'static_analysis_ids_w_activities': self.static_analysis_ids_w_activities}


def start_analysis(files):
    if 'apks' in files:
        filenames = []
        for file in files.getlist('apks'):
            filenames += [apks.save(file).replace('.apk', '')]

        task_ids = []
        apk_filename_to_static_analysis_ids = {}
        for filename in filenames:
            task = celery.send_task('static_analysis_task', args=[filename])
            task_ids += [task.id]
            apk_filename_to_static_analysis_ids[filename] = task.id

        html = result_view_service.render_all_scenario_settings(filenames)

        analysis_state = AnalysisState(task_ids, {}, html, apk_filename_to_static_analysis_ids)
        return jsonify(analysis_state.__json__())
    else:
        return jsonify({'error': True})


def get_analysis_state(state_json):
    static_analysis_tasks = [celery.AsyncResult(id) for id in state_json['static_analysis_ids']]
    finished_static_analysis_tasks = [task for task in static_analysis_tasks if task.state == states.SUCCESS]
    static_analysis_tasks_w_activities = {celery.AsyncResult(id): activity for id, activity
                                          in state_json['static_analysis_ids_w_activities'].iteritems()}

    started_dynamic_analysis_ids = _start_dynamic_analysis(
        finished_static_analysis_tasks,
        static_analysis_tasks_w_activities)

    dynamic_analysis_tasks = [celery.AsyncResult(id) for id in state_json['dynamic_analysis_ids_w_state']]

    html = dict()
    _set_static_analysis_html(finished_static_analysis_tasks, html)
    _set_dynamic_analysis_html(dynamic_analysis_tasks, state_json, html)

    return _create_state(
        static_analysis_tasks,
        dynamic_analysis_tasks,
        started_dynamic_analysis_ids,
        html,
        state_json['apk_filename_to_static_analysis_ids'])


def _flatten(l):
    return [item for sublist in l for item in sublist]


def _start_dynamic_analysis(finished_static_analysis_tasks, static_analysis_tasks_w_activities):
    results = _flatten([_start_dynamic_analysis_for_static_analysis(task) for task in finished_static_analysis_tasks])
    results += [_start_activities_dynamic_analysis(task, activities['activities'], activities['scenario_settings_id'])
                for task, activities in static_analysis_tasks_w_activities.iteritems()]
    return results


def _start_dynamic_analysis_for_static_analysis(static_analysis_task):
    r = DictObject(static_analysis_task.result)

    scenario_datas = scenario_service.get_all_of_user(r.static_analysis_results)
    if not scenario_datas:
        return []

    task_ids = []
    for scenario_data in scenario_datas:
        newtask = celery.send_task(
            'dynamic_analysis_task',
            args=[r.static_analysis_results.apk_filename, scenario_data, r.smart_input_results, SmartInputAssignment()])
        task_ids += [newtask.id]

    return task_ids


def _start_activities_dynamic_analysis(static_analysis_task, activities, scenario_settings_id):
    r = DictObject(static_analysis_task.result)

    scenario_datas = scenario_service.get_for_choosen_activities_and_settings(
        r.static_analysis_results,
        activities,
        scenario_settings_id)
    if not scenario_datas:
        return []

    newtask = celery.send_task(
        'dynamic_analysis_task',
        args=[r.static_analysis_results.apk_filename, scenario_datas[0], r.smart_input_results, SmartInputAssignment()])

    return newtask.id


def _set_static_analysis_html(finished_static_analysis_tasks, html):
    rs = [DictObject(task.result).static_analysis_results for task in finished_static_analysis_tasks]

    for r in rs:
        result_view_service.render_static_analysis_results(r, html)


def _set_dynamic_analysis_html(dynamic_analysis_tasks, state_json, html):
    ids_w_state = state_json['dynamic_analysis_ids_w_state']
    updated_dynamic_analysis_tasks = [task for task in dynamic_analysis_tasks
                                      if task.result and task.result['state_count'] > ids_w_state[task.id]]
    results = [DictObject(task.result) for task in updated_dynamic_analysis_tasks]
    log_analysis_results = _flatten([result.log_analysis_results for result in results
                                    if result.get('log_analysis_results')])
    result_view_service.render_log_analysis_results(log_analysis_results, html)


def _create_state(
        static_analysis_tasks,
        dynamic_analysis_tasks,
        started_dynamic_analysis_ids,
        html,
        apk_filename_to_static_analysis_ids):
    started_dynamic_analysis_ids_w_state = {id: -1 for id in started_dynamic_analysis_ids}
    unfinished_dynamic_analysis_ids_w_state = {task.id: task.result['state_count'] if task.result else -1
                                               for task in dynamic_analysis_tasks
                                               if task.state != states.SUCCESS}
    unfinished_dynamic_analysis_ids_w_state.update(started_dynamic_analysis_ids_w_state)

    unfinished_static_analysis_ids = [task.id for task in static_analysis_tasks if task.state != states.SUCCESS]

    analysis_state = AnalysisState(
        unfinished_static_analysis_ids,
        unfinished_dynamic_analysis_ids_w_state,
        html,
        apk_filename_to_static_analysis_ids)
    return jsonify(analysis_state.__json__())

