"""Collector-local OpenHound application customization."""

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Annotated, Any

import dlt
import typer
from dlt.common.pipeline import LoadInfo
from dlt.extract.pipe import Pipe
from dlt.extract.resource import DltResource
from dlt.extract.source import DltSource
from dlt.pipeline.pipeline import Pipeline
from openhound.cli.collect import collect as collect_cli
from openhound.core.app import Contract, OpenHound
from openhound.core.app import OutputPath  # type: ignore[attr-defined]
from openhound.core.collect import CollectContext, Collector
from openhound.core.progress import Progress

logger = logging.getLogger(__name__)


class _GroupCollector(Collector):
    """Reuse OpenHound's run options and error handling with a fixed pipeline."""

    def __init__(self, pipeline: Pipeline, **kwargs: Any) -> None:
        """Keep the pipeline created before starting group threads."""
        super().__init__(**kwargs)
        self._pipeline = pipeline

    @property
    def pipeline(self) -> Pipeline:
        """Return this group's independent pipeline and working state."""
        return self._pipeline


class OktaCollector(Collector):
    """Run independent collector groups through concurrent DLT pipelines."""

    def __init__(
        self,
        *args: Any,
        group_resolver: Callable[[DltSource], dict[str, list[str]]],
        **kwargs: Any,
    ) -> None:
        """Resolve groups inside the run lifecycle, including telemetry handling."""
        super().__init__(*args, **kwargs)
        self._group_resolver = group_resolver
        self.group_results: dict[str, LoadInfo] = {}

    def run(self, source_object: DltSource, **kwargs: Any) -> LoadInfo:
        """Run whole pipelines concurrently, keeping the existing output dataset."""
        selected = (
            source_object.with_resources(*self.resources)
            if self.resources
            else source_object
        )
        groups = self._group_resolver(selected)
        self.group_results = {}
        if set(groups) <= {"default"}:
            result = super().run(source_object, **kwargs)
            self.group_results["default"] = result
            return result

        runs = {}
        for group, resources in groups.items():
            pipeline = dlt.pipeline(
                pipeline_name=(
                    f"{self.name}_collect"
                    if group == "default"
                    else f"{self.name}_{group}_collect"
                ),
                destination=dlt.destinations.filesystem(
                    bucket_url=str(self.output_path)
                ),
                dataset_name=self.name,
                progress=self.progress.value,
            )
            runner = _GroupCollector(
                pipeline,
                name=self.name,
                output_path=self.output_path,
                progress=self.progress,
                schema_contract=self.schema_contract,
            )
            runs[group] = (runner, selected.with_resources(*resources))

        with ThreadPoolExecutor(max_workers=len(runs)) as executor:
            futures = {
                executor.submit(runner.run, source, **kwargs): group
                for group, (runner, source) in runs.items()
            }
            for future in as_completed(futures):
                group = futures[future]
                self.group_results[group] = future.result()
                logger.info("Collector group completed group=%s", group)

        # Preserve the CLI's single LoadInfo return; retain every result above.
        primary = "default" if "default" in groups else next(iter(groups))
        return self.group_results[primary]


class OktaOpenHound(OpenHound):
    """Okta-local extension point retaining OpenHound's default behavior. We will probably want to port this to OpenHound at one point"""

    def __init__(
        self,
        name: str,
        source_kind: str | None = None,
        help: str = "OpenGraph collector",
    ) -> None:
        """Keep group declarations alongside OpenHound's resource registry."""
        super().__init__(name, source_kind=source_kind, help=help)
        self._collector_groups: dict[str, str] = {}

    def resource(
        self,
        *dlt_args: Any,
        collector_group: str | None = None,
        **dlt_kwargs: Any,
    ) -> Callable[[Callable[..., Any]], DltResource]:
        """Record scheduling metadata while using OpenHound's resource wrapper."""
        if collector_group is not None and not collector_group.strip():
            raise ValueError("collector_group must not be empty")
        upstream = super().resource(*dlt_args, **dlt_kwargs)

        def decorator(func: Callable[..., Any]) -> DltResource:
            """Let OpenHound create and register the resource before labeling it."""
            resource = upstream(func)
            if collector_group is not None:
                self._collector_groups[resource.name] = collector_group
            return resource

        return decorator

    def transformer(
        self,
        *dlt_args: Any,
        collector_group: str | None = None,
        **dlt_kwargs: Any,
    ) -> Callable[[Callable[..., Any]], DltResource]:
        """Record scheduling metadata while using OpenHound's transformer wrapper."""
        if collector_group is not None and not collector_group.strip():
            raise ValueError("collector_group must not be empty")
        upstream = super().transformer(*dlt_args, **dlt_kwargs)

        def decorator(func: Callable[..., Any]) -> DltResource:
            """Let OpenHound create and register the transformer before labeling it."""
            resource = upstream(func)
            if collector_group is not None:
                self._collector_groups[resource.name] = collector_group
            return resource

        return decorator

    def resolve_collector_groups(self, source: DltSource) -> dict[str, list[str]]:
        """Resolve selected resources, inheriting groups through dependency chains."""

        def resolve(pipe: Pipe) -> str:
            """Include unselected parents when validating group inheritance."""
            declared = self._collector_groups.get(pipe.name)
            if pipe.parent is None or pipe.parent.is_empty:
                return declared or "default"
            inherited = resolve(pipe.parent)
            if declared is not None and declared != inherited:
                raise ValueError(
                    f"Resource {pipe.name!r} declares collector group {declared!r} "
                    f"but its parent belongs to {inherited!r}"
                )
            return inherited

        groups: dict[str, list[str]] = {}
        table_groups: dict[Any, str] = {}
        for resource in source.resources.selected.values():
            group = resolve(resource._pipe)
            table = resource.table_name
            if table in table_groups and table_groups[table] != group:
                raise ValueError(
                    f"Table {table!r} is written by collector groups "
                    f"{table_groups[table]!r} and {group!r}"
                )
            table_groups[table] = group
            groups.setdefault(group, []).append(resource.name)
        return groups

    def collect(
        self,
        help: str = "OpenGraph collect pipeline",
        **kwargs: Any,
    ) -> Callable[..., Any]:
        """Register collection with the local runner and unchanged CLI options."""

        def decorator(
            func: Callable[[CollectContext], DltSource],
        ) -> Callable[..., Any]:
            """Bind the source factory to the collection command."""

            def wrapper(
                output_path: OutputPath,
                resources: list[str] = typer.Argument(None),
                progress: Progress = typer.Option(
                    Progress.tqdm, help="Select progress tracker option"
                ),
                tables_contract: Annotated[
                    Contract,
                    typer.Option(
                        help="DLT contract applied when data contains newly seen resources/tables previously not collected",
                    ),
                ] = Contract.evolve,
                columns_contract: Annotated[
                    Contract,
                    typer.Option(
                        help="DLT contract applied when data contains values/keys not found in the Pydantic model",
                    ),
                ] = Contract.evolve,
                data_type_contract: Annotated[
                    Contract,
                    typer.Option(
                        help="DLT contract applied when fields do not match the data types defined in the Pydantic model",
                    ),
                ] = Contract.discard_row,
            ) -> LoadInfo | None:
                """Create the local runner and collect the returned source."""
                collector = OktaCollector(
                    group_resolver=self.resolve_collector_groups,
                    name=self.name,
                    output_path=output_path,
                    resources=resources,
                    progress=progress,
                    schema_contract={
                        "tables": tables_contract,
                        "columns": columns_contract,
                        "data_type": data_type_contract,
                    },
                )
                source = func(CollectContext(pipeline=collector))
                if source:
                    return collector.run(source)
                return None

            logger.debug("Registering collect command for %s", self.name)
            self.collector = wrapper
            return collect_cli.command(name=self.name, help=help)(wrapper)

        return decorator
