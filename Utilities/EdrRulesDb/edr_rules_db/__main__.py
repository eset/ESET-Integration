import asyncio
import json
import logging
import typing as t
import urllib.parse
from asyncio.events import AbstractEventLoop
from importlib import resources
from pathlib import Path
from xml.parsers.expat import ExpatError

import xmltodict
from _asyncio import Task
from aiohttp import ClientSession
from pyhocon import ConfigFactory
from pyhocon.config_tree import ConfigTree

from edr_rules_db.metrics import RuleMetrics


class EdrRuleParsingFailed(Exception):
    pass


class EdrRulesDB:
    def __init__(self, loop: AbstractEventLoop, config: ConfigTree) -> None:
        self._loop = loop
        self._config = config

        self._db_path = Path(self._config.get("db_path")).joinpath("edr_rules_db.json")
        self._edr_rules_list = []

        self._metrics = RuleMetrics()

        self._session: ClientSession | None = None
        self._token: str | None = None

        self._parsing_tasks: list[Task] = []

    async def run(self) -> None:
        logging.info("Processing ...")
        self._session = ClientSession()

        self._token = await self._get_token()

        next_page_token = ""
        while True:
            next_page_token, rules = await self._list_edr_rules_page(next_page_token)
            task = self._loop.create_task(self._parse_rules(rules))
            task.add_done_callback(self._parsing_task_callback)
            self._parsing_tasks.append(task)

            if next_page_token == "":
                logging.info("End of rules")
                break

        # Wait for all running parsing tasks
        await asyncio.gather(*self._parsing_tasks)
        self._db_path.write_text(json.dumps({"edr_rules": self._edr_rules_list}))
        self._metrics.log_metrics()

    async def _get_token(self) -> str:
        headers = {"accept": "application/json", "Content-type": "application/x-www-form-urlencoded"}

        data = urllib.parse.quote(
            f"grant_type=password&username={self._config.get('username')}&password={self._config.get('password')}",
            safe="=&/",
        )

        assert self._session is not None
        async with self._session.post(
            f"{self._config.get('token_host')}/oauth/token", headers=headers, data=data
        ) as resp:
            resp_json = await resp.json()

        return t.cast(str, resp_json["access_token"])

    async def _list_edr_rules_page(self, next_page_token: str) -> tuple[str, list[dict[str, t.Any]]]:
        params: dict[str, str | int] = {"pageSize": 100}
        if next_page_token != "":
            params["pageToken"] = next_page_token
        headers = {"accept": "application/json", "Authorization": f"Bearer {self._token}"}

        assert self._session is not None
        async with self._session.get(
            f"{self._config.get('host')}/v2/edr-rules", headers=headers, params=params
        ) as resp:
            resp_json = await resp.json()

        return resp_json["nextPageToken"], resp_json["rules"]

    async def _parse_rules(self, rules: list[dict[str, t.Any]]) -> None:
        for rule in rules:
            self._metrics.inc_all()

            try:
                rule_dict = self._get_dict_rule_from_xml(rule["xmlDefinition"])
            except EdrRuleParsingFailed as e:
                logging.error(f"Unable parse rule: {rule}")
                logging.debug("Exception", exc_info=e)
                self._metrics.inc_parsing_fail()
                continue

            self._edr_rules_list.append(rule_dict)

    def _parsing_task_callback(self, task: Task) -> None:
        try:
            task.result()
        except Exception as e:
            self._loop.stop()
            raise e

    @staticmethod
    def _get_dict_rule_from_xml(xml_definition: str) -> dict[str, t.Any]:
        try:
            xml_dict = xmltodict.parse(xml_definition)
        except ExpatError as e:
            raise EdrRuleParsingFailed from e

        try:
            rule_dict = xml_dict["rule"]
        except KeyError:
            try:
                rule_dict = xml_dict["Rule"]
            except KeyError as e:
                raise EdrRuleParsingFailed from e

        del rule_dict["definition"]
        if "maliciousTarget" in rule_dict:
            del rule_dict["maliciousTarget"]

        if "action" in rule_dict:
            action = rule_dict.pop("action")
            if isinstance(action, str):
                actions_list = [action]
            else:
                actions_list = [action["@name"]]
        else:
            actions = rule_dict["actions"]["action"]
            if isinstance(actions, dict):
                actions_list = [actions["@name"]]
            else:
                actions_list = [action["@name"] for action in actions]

        rule_dict["actions"] = actions_list

        return rule_dict

    async def aclose(self) -> None:
        logging.info("Closing")
        assert self._session is not None
        await self._session.close()


def main() -> None:
    loop = asyncio.get_event_loop()

    config_path = resources.files(__package__).joinpath("config.conf")
    config = ConfigFactory.parse_file(config_path)
    logging.basicConfig(
        level=logging.DEBUG if config.get("debug", None) else logging.INFO,
        format="%(asctime)s - %(levelname)-8s %(message)s",
    )

    edr_rule_db = EdrRulesDB(loop, config)

    try:
        loop.run_until_complete(edr_rule_db.run())
    except Exception as e:
        logging.error("Get Edr Rules DB was not successful", exc_info=e)
        raise e
    finally:
        loop.run_until_complete(edr_rule_db.aclose())

if __name__ == "__main__":
    main()
