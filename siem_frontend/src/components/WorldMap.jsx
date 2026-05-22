import { useEffect, useRef } from 'react'
import * as d3 from 'd3'
import * as topojson from 'topojson-client'
import worldData from 'world-atlas/countries-110m.json'

export default function WorldMap({ threats, width = 800, height = 400 }) {
  const svgRef = useRef()

  useEffect(() => {
    if (!worldData) return

    const svg = d3.select(svgRef.current)
    svg.selectAll("*").remove()

    // Add a container group for zooming
    const g = svg.append("g")

    const projection = d3.geoNaturalEarth1()
      .scale(width / 5.5)
      .translate([width / 2, height / 1.8])

    const path = d3.geoPath().projection(projection)

    // Zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([1, 8])
      .on("zoom", (event) => {
        g.attr("transform", event.transform)
      })

    svg.call(zoom)

    // Convert topojson to geojson
    const countries = topojson.feature(worldData, worldData.objects.countries)

    // Draw Countries
    g.append("g")
      .attr("class", "countries")
      .selectAll("path")
      .data(countries.features)
      .enter()
      .append("path")
      .attr("d", path)
      .attr("fill", "var(--bg3)")
      .attr("stroke", "var(--ln)")
      .attr("stroke-width", 0.5)
      .style("transition", "fill 0.3s")
      .on("mouseover", function() { d3.select(this).attr("fill", "var(--surface2)") })
      .on("mouseout", function() { d3.select(this).attr("fill", "var(--bg3)") })

    // Draw Threat Points
    const pointsGroup = g.append("g").attr("class", "threats")

    threats.forEach((t, i) => {
      const coords = projection([t.lon || t.longitude || 0, t.lat || t.latitude || 0])
      if (!coords) return

      const color = t.severity === 'critical' ? 'var(--r)' : t.severity === 'high' ? 'var(--o)' : 'var(--y)'

      // Ripple effect
      const ripple = pointsGroup.append("circle")
        .attr("cx", coords[0])
        .attr("cy", coords[1])
        .attr("r", 2)
        .attr("fill", "none")
        .attr("stroke", color)
        .attr("stroke-width", 2)
        .style("opacity", 0.8)

      ripple.transition()
        .duration(2000)
        .delay(i * 100)
        .attr("r", 15)
        .style("opacity", 0)
        .on("end", function repeat() {
            d3.select(this)
              .attr("r", 2)
              .style("opacity", 0.8)
              .transition()
              .duration(2000)
              .attr("r", 15)
              .style("opacity", 0)
              .on("end", repeat)
        })

      // Static point
      pointsGroup.append("circle")
        .attr("cx", coords[0])
        .attr("cy", coords[1])
        .attr("r", 4)
        .attr("fill", color)
        .attr("stroke", "#fff")
        .attr("stroke-width", 1)
        .style("filter", `blur(1px)`)
        .append("title")
        .text(`${t.ip}: ${t.country} (${t.threat_types?.join(', ') || 'attack'})`)
    })

    // Add target point (SIEM Center - approximated)
    const target = projection([-95, 37]) // USA Center
    if (target) {
        g.append("circle")
          .attr("cx", target[0])
          .attr("cy", target[1])
          .attr("r", 5)
          .attr("fill", "var(--b)")
          .attr("stroke", "#fff")
          .style("filter", "drop-shadow(0 0 5px var(--b))")
    }

  }, [threats, width, height])

  return (
    <div className="world-map-container" style={{ width: '100%', overflow: 'hidden', background: 'var(--bg1)', borderRadius: 8, border: '1px solid var(--ln)' }}>
      <svg ref={svgRef} width="100%" height={height} viewBox={`0 0 ${width} ${height}`} style={{ display: 'block' }} />
    </div>
  )
}
